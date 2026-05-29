"""Design-curated synthetic borderline cases (v3): deceptive templates only, no model gate."""

from __future__ import annotations

from typing import Any

from lib.codeql_alert import make_alert, wrap_codeql
from synthetic.generator_v2 import SyntheticCase, _GENERATORS

JAVA_PKG = "org.owasp.benchmark.testcode.blcurated"
REL_PREFIX = f"src/main/java/{JAVA_PKG.replace('.', '/')}"

CWE_QUOTAS_V3: list[tuple[str, int]] = [
    ("xss", 90),
    ("sql-injection", 50),
    ("command-line-injection", 28),
    ("path-injection", 28),
    ("error-message-exposure", 24),
    ("ldapi", 18),
    ("insecure-cookie", 12),
    ("insecure-randomness", 14),
]

DECEPTIVE_VARIANT_BASE: dict[str, int] = {
    "xss": 7,
    "sql-injection": 5,
    "command-line-injection": 1,
    "path-injection": 1,
    "error-message-exposure": 1,
    "ldapi": 1,
    "insecure-cookie": 2,
    "insecure-randomness": 2,
}

FORBIDDEN_JAVA_SUBSTRINGS = ("Synthetic", "SINK:", "borderline", "synthetic")


def case_id(n: int) -> str:
    return f"BLSynthetic{n:05d}"


def class_name(n: int) -> str:
    return f"BlCurated{n:05d}"


def _fix_java_package(java_source: str) -> str:
    return java_source.replace(
        "org.owasp.benchmark.testcode.synthetic",
        JAVA_PKG,
    )


def build_cwe_schedule_v3() -> list[str]:
    schedule: list[str] = []
    for bucket, count in CWE_QUOTAS_V3:
        schedule.extend([bucket] * count)
    if len(schedule) != 264:
        raise ValueError(len(schedule))
    return schedule

def generate_case(seq: int, cwe: str) -> SyntheticCase:
    clazz = class_name(seq)
    modval = DECEPTIVE_VARIANT_BASE.get(cwe, 1)
    variant_n = seq
    if modval > 1:
        variant_n = seq * 3 + divmod(hash(cwe), modval)[1]
    synth = _GENERATORS[cwe](seq, clazz, variant_n)
    synth.case_id = case_id(seq)
    synth.java_source = _fix_java_package(synth.java_source)
    synth.rel_file = f"{REL_PREFIX}/{clazz}.java"
    for bad in FORBIDDEN_JAVA_SUBSTRINGS:
        if bad in synth.java_source:
            raise ValueError(f"{synth.case_id} forbidden {bad!r}")
    return synth


def to_case_json(sc: SyntheticCase) -> dict[str, Any]:
    alert = make_alert(
        rule_id=sc.rule_id,
        rel_uri=sc.rel_file,
        start_line=sc.sink_line,
        message=sc.message,
    )
    base = wrap_codeql([alert])
    base.update(
        {
            "case_id": sc.case_id,
            "gold_track": "BL",
            "acceptable_labels": ["TP", "FP"],
            "synthetic": True,
            "synthetic_tier": "curated_v3_design",
            "validation_tier": "design_curated_no_model_gate",
            "cwe_bucket": sc.cwe_bucket,
            "template_id": sc.template_id,
            "borderline_rationale": sc.borderline_rationale,
            "tp_argument": sc.tp_argument,
            "fp_argument": sc.fp_argument,
            "codeql_origin": "synthetic_template_aligned",
            "benchmark_real_vuln": None,
            "validation_disagreement": None,
            "validation_labels": None,
            "validation_tp_rate": None,
        }
    )
    return base


def generate_curated_v3() -> list[tuple[SyntheticCase, dict[str, Any]]]:
    out: list[tuple[SyntheticCase, dict[str, Any]]] = []
    for seq, bucket in enumerate(build_cwe_schedule_v3(), start=1):
        sc = generate_case(seq, bucket)
        out.append((sc, to_case_json(sc)))
    return out
