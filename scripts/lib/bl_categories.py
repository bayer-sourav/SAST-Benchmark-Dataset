"""Borderline v4 category definitions and validation."""

from __future__ import annotations

from typing import Literal

BorderlineCategory = Literal[
    "bypassable_mitigation",
    "dns_rebinding",
    "deployment_trust",
    "semi_trusted_input",
]

CATEGORIES: tuple[BorderlineCategory, ...] = (
    "bypassable_mitigation",
    "dns_rebinding",
    "deployment_trust",
    "semi_trusted_input",
)

CATEGORY_LABELS: dict[BorderlineCategory, str] = {
    "bypassable_mitigation": "Bypassable-but-non-trivial mitigations",
    "dns_rebinding": "DNS rebinding windows",
    "deployment_trust": "Deployment/infrastructure trust dependencies",
    "semi_trusted_input": "Semi-trusted or partially-controlled inputs",
}

BL_V4_ACCEPTABLE_LABELS = ["BL"]
BL_V4_VERSION = "v4"


def validate_category(cat: str) -> BorderlineCategory:
    if cat not in CATEGORIES:
        raise ValueError(f"unknown borderline_category {cat!r}; expected one of {CATEGORIES}")
    return cat  # type: ignore[return-value]
