#!/usr/bin/env python3
"""Build all-synthetic BL v4 pilot (default 10 per category = 40 cases)."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))

from lib.bl_categories import BL_V4_ACCEPTABLE_LABELS, BL_V4_VERSION, CATEGORIES  # noqa: E402
from lib.publish_case import publish_synthetic_case  # noqa: E402
from synthetic.curated_bl_v4 import FORBIDDEN, generate_pilot_pool, to_case_json  # noqa: E402


def validate_case(case: dict) -> list[str]:
    errors: list[str] = []
    if case.get("gold_track") != "BL":
        errors.append("gold_track must be BL")
    if case.get("acceptable_labels") != BL_V4_ACCEPTABLE_LABELS:
        errors.append(f"acceptable_labels must be {BL_V4_ACCEPTABLE_LABELS}")
    if case.get("borderline_version") != BL_V4_VERSION:
        errors.append("borderline_version must be v4")
    cat = case.get("borderline_category")
    if cat not in CATEGORIES:
        errors.append(f"invalid borderline_category {cat!r}")
    for key in ("bl_argument", "tp_argument", "fp_argument", "borderline_rationale"):
        if not str(case.get(key) or "").strip():
            errors.append(f"missing {key}")
    qs = case.get("bl_context_questions") or []
    if len(qs) < 2:
        errors.append("need at least 2 bl_context_questions")
    if not case.get("synthetic"):
        errors.append("pilot must be synthetic-only")
    return errors


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "BenchmarkJava" / "borderline_pilot")
    ap.add_argument("--per-category", type=int, default=10)
    ap.add_argument("--exemplar-out", type=Path, default=None,
                    help="Also write one DNS-rebind exemplar bundle for few-shot (BLv4p_exemplar)")
    args = ap.parse_args()

    out = args.out.resolve()
    if out.exists():
        shutil.rmtree(out)
    pilot_dir = out / "pilot"
    pilot_dir.mkdir(parents=True)

    manifest_cases: list[dict] = []
    cat_counts: Counter[str] = Counter()
    all_errors: list[str] = []

    for sc in generate_pilot_pool(args.per_category):
        for bad in FORBIDDEN:
            if bad.lower() in sc.java_source.lower():
                raise ValueError(f"{sc.case_id} contains forbidden {bad!r}")
        case_json = to_case_json(sc) | {"pilot": True, "synthetic_only_pilot": True}
        errs = validate_case(case_json)
        if errs:
            all_errors.extend([f"{sc.case_id}: {e}" for e in errs])
        pub = publish_synthetic_case(
            bundle_dir=pilot_dir,
            case_id=sc.case_id,
            java_source=sc.java_source,
            rel_file=sc.rel_file,
            case_json=case_json,
        )
        pub["borderline_category"] = sc.borderline_category
        pub["template_id"] = sc.template_id
        manifest_cases.append(pub)
        cat_counts[sc.borderline_category] += 1

    if all_errors:
        raise SystemExit("Validation failed:\n" + "\n".join(all_errors))

    # Few-shot exemplar (DNS rebind — not in pilot eval set)
    exemplar_dir = out / "exemplar"
    from synthetic.curated_bl_v4 import BlV4Case, _assemble, JAVA_PKG  # noqa: E402

    ex_rel = f"src/main/java/{JAVA_PKG.replace('.', '/')}/BlV4_exemplar.java"
    ex_body = """
        String target = param;
        java.net.InetAddress addr = java.net.InetAddress.getByName(target);
        if (addr.isLoopbackAddress()) return;
        java.net.URL url = new java.net.URL("http://" + target + "/api");
        url.openStream(); @sink
    """
    ex_java, ex_sink = _assemble("BlV4_exemplar", "blv4/exemplar", ex_body)
    ex_sc = BlV4Case(
        case_id="BLv4p_exemplar",
        borderline_category="dns_rebinding",
        cwe_bucket="ssrf",
        java_source=ex_java,
        rel_file=ex_rel,
        sink_line=ex_sink,
        rule_id="java/ssrf",
        message="Separate DNS resolve and fetch (few-shot exemplar).",
        template_id="dns-rebind-exemplar",
        borderline_rationale="DNS rebinding windows",
        bl_argument="Resolve-then-fetch: exploitability depends on DNS TTL and egress controls not shown in code.",
        tp_argument="DNS rebinding could reach internal targets.",
        fp_argument="Network policy may block internal ranges regardless.",
        bl_context_questions=["DNS TTL?", "Egress filtered?", "Same connection for resolve and fetch?"],
    )
    publish_synthetic_case(
        bundle_dir=exemplar_dir,
        case_id="BLv4p_exemplar",
        java_source=ex_java,
        rel_file=ex_rel,
        case_json=to_case_json(ex_sc) | {"few_shot_exemplar": True},
    )

    manifest = {
        "dataset": "benchmark_java_borderline_v4_pilot",
        "borderline_version": BL_V4_VERSION,
        "synthetic_only": True,
        "n_cases": len(manifest_cases),
        "per_category": args.per_category,
        "borderline_category_counts": dict(sorted(cat_counts.items())),
        "acceptable_labels": BL_V4_ACCEPTABLE_LABELS,
        "validation": "passed",
        "cases": manifest_cases,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({
        "out": str(out),
        "n_cases": len(manifest_cases),
        "by_category": dict(cat_counts),
        "synthetic_only": True,
        "validation": "passed",
    }, indent=2))


if __name__ == "__main__":
    main()
