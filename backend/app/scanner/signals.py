"""
Shared helpers for scoring finding confidence based on corroborating signals,
and for comparing a probe response against a baseline response to filter out
noise (timestamps, pagination, transient errors) that isn't a real signal.
"""
from typing import Any, Dict, List, Optional
import json


def confidence_from_signals(signals: List[str]) -> str:
    """Map the number of independent corroborating signals to a confidence level."""
    count = len(signals)
    if count >= 3:
        return "high"
    if count == 2:
        return "medium"
    return "low"


def is_html_context(content_type: str) -> bool:
    return "text/html" in (content_type or "").lower()


def _owner_fields(obj: Dict[str, Any]) -> Dict[str, Any]:
    keys = ("user_id", "owner", "owner_id", "email", "username", "account_id", "created_by")
    return {k: obj[k] for k in keys if k in obj}


def diff_json_bodies(baseline_text: str, probe_text: str) -> Dict[str, Any]:
    """
    Structured comparison of two JSON response bodies, focused on
    owner-identifying fields rather than raw text/length diffing (which is
    triggered by timestamps, pagination, and other harmless noise).

    Returns a dict: {"parsed": bool, "owner_fields_differ": bool, "differing_fields": [...]}
    """
    try:
        baseline_obj = json.loads(baseline_text)
        probe_obj = json.loads(probe_text)
    except (ValueError, TypeError):
        return {"parsed": False, "owner_fields_differ": False, "differing_fields": []}

    if not isinstance(baseline_obj, dict) or not isinstance(probe_obj, dict):
        return {"parsed": False, "owner_fields_differ": False, "differing_fields": []}

    baseline_owner = _owner_fields(baseline_obj)
    probe_owner = _owner_fields(probe_obj)

    differing = [
        k for k in set(baseline_owner) | set(probe_owner)
        if baseline_owner.get(k) != probe_owner.get(k)
    ]

    return {
        "parsed": True,
        "owner_fields_differ": bool(differing),
        "differing_fields": differing,
    }


def value_reflected(body: str, value: Any) -> bool:
    """Whether a specific injected value (not just a field name) appears in a response body."""
    if value is None:
        return False
    return str(value).lower() in (body or "").lower()
