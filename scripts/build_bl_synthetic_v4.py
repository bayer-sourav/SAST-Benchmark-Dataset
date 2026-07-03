#!/usr/bin/env python3
"""Publish borderline v4 synthetic pool to .work/bl_synthetic_v4/."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from lib.publish_case import publish_synthetic_case  # noqa: E402
from synthetic.curated_bl_v4 import FORBIDDEN, generate_pool, to_case_json  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=SCRIPTS_DIR.parent / ".work" / "bl_synthetic_v4")
    args = ap.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    manifest_rows: list[dict] = []
    for sc in generate_pool():
        for bad in FORBIDDEN:
            if bad.lower() in sc.java_source.lower():
                raise ValueError(f"{sc.case_id} contains forbidden {bad!r}")
        case_json = to_case_json(sc)
        row = publish_synthetic_case(
            bundle_dir=out,
            case_id=sc.case_id,
            java_source=sc.java_source,
            rel_file=sc.rel_file,
            case_json=case_json,
        )
        row["borderline_category"] = sc.borderline_category
        manifest_rows.append(row)

    manifest = {
        "dataset": "bl_synthetic_v4",
        "n_cases": len(manifest_rows),
        "quotas": __import__("synthetic.curated_bl_v4", fromlist=["SYNTHETIC_QUOTAS"]).SYNTHETIC_QUOTAS,
        "cases": manifest_rows,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"n_cases": len(manifest_rows), "out": str(out)}, indent=2))


if __name__ == "__main__":
    main()
