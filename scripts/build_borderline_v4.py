#!/usr/bin/env python3
"""Build BenchmarkJava/borderline v4: principled empirical + synthetic (900 total)."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))

from lib.bl_categories import BL_V4_ACCEPTABLE_LABELS, BL_V4_VERSION  # noqa: E402
from lib.publish_case import publish_real_case, publish_synthetic_case  # noqa: E402
from lib.select_balanced import stratified_split, stratified_split_equal_test_per_category  # noqa: E402
from synthetic.curated_bl_v4 import (  # noqa: E402
    FORBIDDEN,
    FULL_SYNTHETIC_QUOTAS,
    SYNTHETIC_QUOTAS,
    generate_pool,
    to_case_json,
)

SEED = 42
TARGET = 900
SPLIT = {"train": 500, "validation": 200, "test": 200}
EMPIRICAL_TARGET = 500
SYNTHETIC_TARGET = 400


def _run_tagger(report: Path, sast_root: Path, bench_java: Path) -> list[dict]:
    subprocess.run(
        [
            sys.executable,
            str(SCRIPTS_DIR / "tag_empirical_bl_v4.py"),
            "--report",
            str(report),
            "--sast-root",
            str(sast_root),
            "--bench-java",
            str(bench_java),
        ],
        check=True,
    )
    data = json.loads(report.read_text(encoding="utf-8"))
    return data["cases"]


def _pick_empirical(pool: list[dict], n: int) -> list[dict]:
    """Stratify by borderline_category × cwe_bucket, prefer diverse pattern_tag."""
    pool = sorted(pool, key=lambda r: (r["borderline_category"], r["cwe_bucket"], r["case_id"]))
    # round-robin across category buckets
    by_key: dict[tuple[str, str], list[dict]] = {}
    for row in pool:
        key = (row["borderline_category"], row["cwe_bucket"])
        by_key.setdefault(key, []).append(row)
    picked: list[dict] = []
    keys = sorted(by_key.keys())
    idx = 0
    while len(picked) < n and by_key:
        key = keys[idx % len(keys)]
        bucket = by_key.get(key) or []
        if bucket:
            picked.append(bucket.pop(0))
            if not bucket:
                by_key.pop(key, None)
                keys = sorted(by_key.keys())
                if not keys:
                    break
        idx += 1
    if len(picked) < n:
        raise SystemExit(f"Need {n} empirical v4 cases, only picked {len(picked)}")
    return picked[:n]


def _publish_empirical(
    rows: list[dict],
    bench_java: Path,
    staging: Path,
) -> list[dict]:
    staging.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []
    for row in rows:
        case_path = Path(row["corpus_path"])
        case = json.loads(case_path.read_text(encoding="utf-8"))
        extra = {
            "gold_track": "BL",
            "acceptable_labels": BL_V4_ACCEPTABLE_LABELS,
            "borderline_version": BL_V4_VERSION,
            "borderline_category": row["borderline_category"],
            "borderline_rationale": row["borderline_rationale"],
            "bl_argument": row["borderline_rationale"],
            "tp_argument": "Escalate if bypass/mitigation failure is realistic in production.",
            "fp_argument": "Dismiss if deployment policy treats this mitigation as sufficient.",
            "bl_context_questions": ["What is the deployment context for this endpoint?"],
            "dispute_resolution": "TP|FP disagreement → BL",
            "synthetic": False,
            "validation_tier": "empirical_v4_tagged",
            "pattern_tag": row.get("pattern_tag"),
            "source_track": row.get("source_track"),
            "cwe_bucket": row.get("cwe_bucket"),
        }
        pub = publish_real_case(
            case_path=case_path,
            bench_java_root=bench_java,
            bundle_dir=staging,
            gold_track="BL",
            extra=extra,
        )
        pub["borderline_category"] = row["borderline_category"]
        manifest.append(pub)
    return manifest


def _publish_synthetic(staging: Path, quotas: dict[str, int]) -> list[dict]:
    staging.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []
    pool = generate_pool(quotas=quotas)
    expected = sum(quotas.values())
    if len(pool) != expected:
        raise SystemExit(f"Expected {expected} synthetic cases, generated {len(pool)}")
    for sc in pool:
        for bad in FORBIDDEN:
            if bad.lower() in sc.java_source.lower():
                raise ValueError(f"{sc.case_id} forbidden {bad!r}")
        pub = publish_synthetic_case(
            bundle_dir=staging,
            case_id=sc.case_id,
            java_source=sc.java_source,
            rel_file=sc.rel_file,
            case_json=to_case_json(sc),
        )
        pub["borderline_category"] = sc.borderline_category
        manifest.append(pub)
    return manifest


def _merge_and_split(
    cases: list[dict],
    out_root: Path,
    *,
    staging_dir: Path,
    composition: dict[str, int],
    selection: str,
    stratify_by: str = "borderline_category",
    equal_test_per_category: bool = False,
) -> None:
    for row in cases:
        row["_stratify_bucket"] = row.get(stratify_by) or "unknown"

    split_fn = stratified_split_equal_test_per_category if equal_test_per_category else stratified_split
    splits = split_fn(
        cases,
        train_n=SPLIT["train"],
        val_n=SPLIT["validation"],
        test_n=SPLIT["test"],
        seed=SEED,
        **({"category_key": stratify_by} if equal_test_per_category else {"bucket_key": "_stratify_bucket"}),
    )

    for row in cases:
        cat = row.get("borderline_category", "unknown")
        cwe = row.get("cwe_bucket") or "unknown"
        row["cwe_bucket"] = f"{cat}|{cwe}"
        row.pop("_stratify_bucket", None)

    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True)

    id_to_bundle: dict[str, Path] = {}
    for bundle in staging_dir.iterdir():
        if bundle.is_dir():
            id_to_bundle[bundle.name] = bundle

    manifest_rows: list[dict] = []
    cat_counts: Counter[str] = Counter()
    for split_name, entries in splits.items():
        for ent in entries:
            cid = ent["case_id"]
            src = id_to_bundle.get(cid)
            if not src:
                raise FileNotFoundError(cid)
            dest = out_root / split_name / cid
            shutil.copytree(src, dest)
            case_path = dest / "case.json"
            case = json.loads(case_path.read_text(encoding="utf-8"))
            case["split"] = split_name
            case_path.write_text(json.dumps(case, ensure_ascii=False, indent=2), encoding="utf-8")
            cat_counts[case.get("borderline_category", "unknown")] += 1
            manifest_rows.append(
                {
                    "case_id": cid,
                    "split": split_name,
                    "bundle": f"borderline/{split_name}/{cid}",
                    "borderline_category": case.get("borderline_category"),
                    "cwe_bucket": case.get("cwe_bucket"),
                    "synthetic": bool(case.get("synthetic")),
                }
            )

    manifest = {
        "dataset": "benchmark_java_borderline_v4",
        "class": "borderline",
        "gold_track": "BL",
        "borderline_version": BL_V4_VERSION,
        "acceptable_labels": BL_V4_ACCEPTABLE_LABELS,
        "principle": "Engineer needs additional context before TP/FP call",
        "seed": SEED,
        "n_cases": TARGET,
        "splits": SPLIT,
        "composition": composition,
        "borderline_category_counts": dict(sorted(cat_counts.items())),
        "selection": selection,
        "cases": manifest_rows,
    }
    (out_root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "BenchmarkJava" / "borderline")
    ap.add_argument("--sast-root", type=Path, default=REPO_ROOT.parent / "SAST")
    ap.add_argument("--bench-java", type=Path, default=REPO_ROOT / "BenchmarkJava")
    ap.add_argument(
        "--all-synthetic",
        action="store_true",
        help="900 curated synthetic cases only (no OWASP empirical)",
    )
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.all_synthetic:
        quotas = FULL_SYNTHETIC_QUOTAS
        if args.dry_run:
            print(
                json.dumps(
                    {
                        "mode": "all_synthetic",
                        "n_cases": sum(quotas.values()),
                        "quotas": quotas,
                    },
                    indent=2,
                )
            )
            return

        syn_staging = REPO_ROOT / ".work" / "_bl_v4_syn_staging"
        if syn_staging.exists():
            shutil.rmtree(syn_staging)
        syn_manifest = _publish_synthetic(syn_staging, quotas)
        _merge_and_split(
            syn_manifest,
            args.out.resolve(),
            staging_dir=syn_staging,
            composition={"empirical": 0, "synthetic": TARGET},
            selection="v4_all_synthetic_curated_calibrated_v2",
            equal_test_per_category=True,
        )
        print(f"Published all-synthetic borderline v4 -> {args.out}")
        return

    report = REPO_ROOT / ".work" / "bl_v4_empirical_pool.json"
    pool = _run_tagger(report, args.sast_root.resolve(), args.bench_java.resolve())
    empirical_rows = _pick_empirical(pool, EMPIRICAL_TARGET)

    if args.dry_run:
        print(
            json.dumps(
                {
                    "pool_size": len(pool),
                    "empirical_pick": len(empirical_rows),
                    "by_category": dict(Counter(r["borderline_category"] for r in empirical_rows)),
                    "synthetic": SYNTHETIC_TARGET,
                },
                indent=2,
            )
        )
        return

    emp_staging = REPO_ROOT / ".work" / "_bl_v4_emp_staging"
    syn_staging = REPO_ROOT / ".work" / "_bl_v4_syn_staging"
    if emp_staging.exists():
        shutil.rmtree(emp_staging)
    if syn_staging.exists():
        shutil.rmtree(syn_staging)

    emp_manifest = _publish_empirical(empirical_rows, args.bench_java.resolve(), emp_staging)
    syn_manifest = _publish_synthetic(syn_staging, SYNTHETIC_QUOTAS)
    combined_staging = REPO_ROOT / ".work" / "_bl_v4_combined_staging"
    if combined_staging.exists():
        shutil.rmtree(combined_staging)
    combined_staging.mkdir(parents=True)
    for staging in (emp_staging, syn_staging):
        for bundle in staging.iterdir():
            if bundle.is_dir():
                shutil.copytree(bundle, combined_staging / bundle.name)
    _merge_and_split(
        emp_manifest + syn_manifest,
        args.out.resolve(),
        staging_dir=combined_staging,
        composition={"empirical": EMPIRICAL_TARGET, "synthetic": SYNTHETIC_TARGET},
        selection="v4_principled_tagged_empirical_plus_curated_synthetic",
    )
    print(f"Published borderline v4 -> {args.out}")


if __name__ == "__main__":
    main()
