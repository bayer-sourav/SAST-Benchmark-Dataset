#!/usr/bin/env python3
"""Publish 264 design-curated synthetic borderline cases to a staging directory."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from lib.publish_case import publish_synthetic_case  # noqa: E402
from synthetic.curated_bl_v3 import generate_curated_v3  # noqa: E402

N = 264


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--out",
        type=Path,
        default=SCRIPTS_DIR.parent / ".work" / "bl_synthetic_264",
    )
    args = ap.parse_args()
    out = args.out.expanduser().resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    rows: list[dict] = []
    cwe_counts: Counter[str] = Counter()
    for sc, case_json in generate_curated_v3():
        row = publish_synthetic_case(
            bundle_dir=out,
            case_id=sc.case_id,
            java_source=sc.java_source,
            rel_file=sc.rel_file,
            case_json=case_json,
        )
        row["cwe_bucket"] = sc.cwe_bucket
        row["template_id"] = sc.template_id
        rows.append(row)
        cwe_counts[sc.cwe_bucket] += 1

    manifest = {
        "dataset": "benchmark_java_borderline_synthetic_v3",
        "n_cases": N,
        "synthetic_tier": "curated_v3_design",
        "validation_tier": "design_curated_no_model_gate",
        "acceptable_labels": ["TP", "FP"],
        "cwe_bucket_counts": dict(sorted(cwe_counts.items())),
        "cases": rows,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Published {len(rows)} synthetic cases -> {out}")


if __name__ == "__main__":
    main()
