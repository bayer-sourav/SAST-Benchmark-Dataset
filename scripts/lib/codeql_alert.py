"""Build minimal CodeQL SARIF-like alert entries for synthetic cases."""

from __future__ import annotations

from typing import Any


def make_alert(
    *,
    rule_id: str,
    rel_uri: str,
    start_line: int,
    end_line: int | None = None,
    message: str,
    start_column: int = 9,
    end_column: int = 40,
) -> dict[str, Any]:
    end_line = end_line or start_line
    short_rule = rule_id.split("/")[-1] if "/" in rule_id else rule_id
    return {
        "ruleId": rule_id,
        "ruleIndex": 0,
        "rule": {"id": rule_id, "index": 0},
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": rel_uri,
                        "uriBaseId": "%SRCROOT%",
                        "index": 0,
                    },
                    "region": {
                        "startLine": start_line,
                        "startColumn": start_column,
                        "endLine": end_line,
                        "endColumn": end_column,
                    },
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": f"synthetic-{short_rule}",
            "primaryLocationStartColumnFingerprint": "0",
        },
    }


def wrap_codeql(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    return {"tool": ["CodeQL"], "raw_output": {"CodeQL": alerts}}
