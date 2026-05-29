"""CodeQL rule-id bucket helpers."""

from __future__ import annotations

from typing import Any


def cwe_bucket(case: dict[str, Any]) -> str:
    raw = case.get("raw_output") or {}
    if not isinstance(raw, dict):
        return "unknown"
    for entries in raw.values():
        if not isinstance(entries, list) or not entries:
            continue
        first = entries[0] if isinstance(entries[0], dict) else {}
        rule_id = str(first.get("ruleId", "") or "")
        if "/" in rule_id:
            return rule_id.split("/")[-1].lower()
        if rule_id:
            return rule_id.lower()
    return "unknown"
