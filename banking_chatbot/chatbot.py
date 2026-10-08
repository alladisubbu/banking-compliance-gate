"""
Module 3 — Banking Chatbot (lab stub)
Extended in Module 6 Project 3 with PCI DSS compliance guardrails.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from llm_client import get_llm_client, resolve_model

load_dotenv()

# In-memory session state
_session_financial_query_count = 0
MAX_FINANCIAL_QUERIES_PER_SESSION = 20

FINANCIAL_KEYWORDS = frozenset({
    "balance", "transfer", "account", "statement", "loan",
    "credit", "debit", "transaction", "payment",
})


def is_financial_query(user_message: str) -> bool:
    """Return True if the message looks like a financial query."""
    tokens = set(user_message.lower().split())
    return bool(tokens & FINANCIAL_KEYWORDS)


def pre_response_pii_filter(text: str) -> str:
    """
    Mask PII in response text per PCI DSS requirements.
    - Card numbers: show last 4 digits only
    - SSN: show last 4 digits only
    - Account numbers: show last 4 digits only
    - Email: partial masking
    - Phone: partial masking
    """
    # Card numbers (16 digits with optional spaces/dashes)
    text = re.sub(
        r'\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-])(\d{4})\b',
        r'****-****-****-\2',
        text
    )

    # SSN (XXX-XX-XXXX format)
    text = re.sub(
        r'\b(\d{3})-(\d{2})-(\d{4})\b',
        r'***-**-\3',
        text
    )

    # Account numbers (8-12 digits)
    text = re.sub(
        r'\b(account\s+(?:number\s+)?|acct\s+)(\d{4,8})(\d{4})\b',
        r'\1****\3',
        text,
        flags=re.IGNORECASE
    )

    # Email addresses
    text = re.sub(
        r'\b([a-zA-Z0-9._%+-])[a-zA-Z0-9._%+-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
        r'\1***@\2',
        text
    )

    # Phone numbers (various formats)
    text = re.sub(
        r'\b(\d{3})[\-\.\s]?(\d{3})[\-\.\s]?(\d{4})\b',
        r'\1-***-\3',
        text
    )

    return text


def rate_limit_check() -> tuple[bool, str]:
    """
    Check if rate limit for financial queries has been exceeded.
    Returns (allowed, error_message).
    """
    global _session_financial_query_count

    if _session_financial_query_count >= MAX_FINANCIAL_QUERIES_PER_SESSION:
        return False, f"Rate limit exceeded: maximum {MAX_FINANCIAL_QUERIES_PER_SESSION} financial queries per session"

    return True, ""


def write_audit_log_entry(
    event_type: str,
    user_message: str,
    response: str | None = None,
    metadata: dict[str, Any] | None = None
) -> None:
    """
    Write audit log entry in JSONL format to audit_log/chatbot_tool_calls.jsonl.
    All PII is masked before logging.
    """
    audit_dir = Path("audit_log")
    audit_dir.mkdir(exist_ok=True)

    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "user_message": pre_response_pii_filter(user_message),
        "response": pre_response_pii_filter(response) if response else None,
        "metadata": metadata or {},
    }

    with open(audit_dir / "chatbot_tool_calls.jsonl", "a") as f:
        f.write(json.dumps(log_entry) + "\n")


def call_claude(user_message: str, tools: list[dict[str, Any]] | None = None) -> str:
    """Send a user message to Claude and return the text response."""
    client = get_llm_client()
    response = client.messages.create(
        model=resolve_model("claude-sonnet-4-5"),
        max_tokens=1024,
        tools=tools or [],
        messages=[{"role": "user", "content": user_message}],
    )
    for block in response.content:
        if block.type == "text":
            return block.text
    return ""


def run_with_guardrails(user_message: str, tools: list[dict[str, Any]] | None = None) -> str:
    """
    Process user message through all PCI DSS compliance guardrails:
    1. Rate limit check (if financial query)
    2. Call Claude API
    3. PII filtering on response
    4. Audit logging
    """
    global _session_financial_query_count

    is_financial = is_financial_query(user_message)

    # Check rate limit for financial queries
    if is_financial:
        allowed, error_msg = rate_limit_check()
        if not allowed:
            write_audit_log_entry(
                event_type="rate_limit_exceeded",
                user_message=user_message,
                response=error_msg,
                metadata={"query_count": _session_financial_query_count}
            )
            return error_msg

        _session_financial_query_count += 1

    # Call Claude API
    try:
        raw_response = call_claude(user_message, tools)

        # Apply PII filter
        filtered_response = pre_response_pii_filter(raw_response)

        # Audit log
        write_audit_log_entry(
            event_type="financial_query" if is_financial else "general_query",
            user_message=user_message,
            response=filtered_response,
            metadata={
                "query_count": _session_financial_query_count if is_financial else None,
                "tools_available": len(tools) if tools else 0,
            }
        )

        return filtered_response

    except Exception as e:
        # Log error without exposing stack trace
        error_msg = "An error occurred processing your request. Please try again."
        write_audit_log_entry(
            event_type="error",
            user_message=user_message,
            response=error_msg,
            metadata={"error_type": type(e).__name__}
        )
        return error_msg


def handle_message(user_message: str) -> str:
    """Chatbot handler with PCI DSS guardrails."""
    return run_with_guardrails(user_message)


if __name__ == "__main__":
    print(handle_message("What services does Heritage National Bank offer?"))
