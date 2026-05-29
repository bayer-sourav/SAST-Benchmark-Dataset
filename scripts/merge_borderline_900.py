#!/usr/bin/env python3
"""Merge empirical borderline (636) + design synthetic (264) and re-split to 900 total."""

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

from lib.select_balanced import stratified_split  # noqa: E402

SEED = 42
TARGET = 900
SPLIT = {"train": 500, "validation": 200, "test": 200}
FORBIDDEN_JAVA = ("Synthetic", "SINK:", "borderline")


def _load_pool_cases(pool_dir: Path) -> list[dict]:
    rows: list[dict] = []
    for bundle in sorted(p for p in pool_dir.iterdir() if p.is_dir()):
        case_path = bundle / "case.json"
        if not case_path.is_file():
            continue
        case = json.loads(case_path.read_text(encoding="utf-8"))
        rows.append(
            {
                "case_id": case["case_id"],
                "cwe_bucket": case.get("cwe_bucket", "unknown"),
                "bundle": bundle,
                "synthetic": bool(case.get("synthetic")),
            }
        )
    return rows


def _load_empirical(empirical_dir: Path) -> list[dict]:
    rows: list[dict] = []
    for split in ("train", "validation", "test"):
        split_dir = empirical_dir / split
        if not split_dir.is_dir():
            continue
        for bundle in sorted(p for p in split_dir.iterdir() if p.is_dir()):
            case_path = bundle / "case.json"
            if not case_path.is_file():
                continue
            case = json.loads(case_path.read_text(encoding="utf-8"))
            rows.append(
                {
                    "case_id": case["case_id"],
                    "cwe_bucket": case.get("cwe_bucket", "unknown"),
                    "bundle": bundle,
                    "synthetic": bool(case.get("synthetic")),
                }
            )
    return rows


def _copy_bundle(src: Path, dest_root: Path, split: str, case_id: str) -> Path:
    dest = dest_root / split / case_id
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    case_path = dest / "case.json"
    case = json.loads(case_path.read_text(encoding="utf-8"))
    case["split"] = split
    case_path.write_text(json.dumps(case, ensure_ascii=False, indent=2), encoding="utf-8")
    return dest


def _scan_java_forbidden(out_root: Path) -> list[str]:
    bad: list[str] = []
    for java in out_root.rglob("*.java"):
        text = java.read_text(encoding="utf-8", errors="replace")
        for token in FORBIDDEN_JAVA:
            if token in text:
                bad.append(f"{java}: contains {token!r}")
    return bad

def _update_dataset_summary(manifest: dict) -> None:
    summary_path = REPO_ROOT / "BenchmarkJava" / "DATASET_SUMMARY.json"
    if not summary_path.is_file():
        return
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    bl = summary.setdefault("classes", {}).setdefault("borderline", {})
    bl.update(
        {
            "dataset": manifest["dataset"],
            "class": "borderline",
            "gold_track": "BL",
            "n_cases": manifest["n_cases"],
            "splits": manifest["splits"],
            "selection": manifest["selection"],
            "validation_tier": manifest.get("validation_tier"),
            "synthetic_tier": manifest.get("synthetic_tier"),
            "note": manifest.get("note"),
        }
    )
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def merge_borderline(*, empirical_dir: Path, synthetic_pool: Path, out_dir: Path, in_place: bool) -> dict:
    empirical = _load_empirical(empirical_dir)
    synthetic = _load_pool_cases(synthetic_pool)
    if len(empirical) != 636:
        raise SystemExit(f"Expected 636 empirical cases, found {len(empirical)}")
    if len(synthetic) != 264:
        raise SystemExit(f"Expected 264 synthetic cases, found {len(synthetic)}")

    combined = empirical + synthetic
    ids = [r["case_id"] for r in combined]
    if len(set(ids)) != len(ids):
        dupes = sorted({x for x in ids if ids.count(x) > 1})
        raise SystemExit(f"Duplicate case_ids: {dupes[:10]}")

    splits = stratified_split(
        combined,
        train_n=SPLIT["train"],
        val_n=SPLIT["validation"],
        test_n=SPLIT["test"],
        seed=SEED,
    )

    staging = out_dir
    if in_place:
        staging = empirical_dir.parent / ".work" / "borderline_900_staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    manifest_rows: list[dict] = []
    cwe_counts: Counter[str] = Counter()
    synth_n = 0
    emp_n = 0
    for split_name, entries in splits.items():
        for ent in entries:
            dest = _copy_bundle(ent["bundle"], staging, split_name, ent["case_id"])
            case = json.loads((dest / "case.json").read_text(encoding="utf-8"))
            rel_file = case.get("file", "")
            manifest_rows.append(
                {
                    "case_id": ent["case_id"],
                    "bundle": f"borderline/{split_name}/{ent['case_id']}",
                    "cwe_bucket": ent["cwe_bucket"],
                    "source": rel_file,
                    "synthetic": ent["synthetic"],
                }
            )
            cwe_counts[ent["cwe_bucket"]] += 1
            if ent["synthetic"]:
                synth_n += 1
            else:
                emp_n += 1

    manifest = {
        "dataset": "benchmark_java_borderline_v2",
        "class": "borderline",
        "gold_track": "BL",
        "seed": SEED,
        "n_cases": TARGET,
        "splits": SPLIT,
        "cwe_bucket_counts": dict(sorted(cwe_counts.items())),
        "selection": "empirical_636_plus_curated_synthetic_264",
        "validation_tier": "mixed_empirical_tp_fp_and_design_curated",
        "synthetic_tier": "curated_v3_design",
        "acceptable_labels": ["TP", "FP"],
        "self_contained": True,
        "composition": {"empirical": emp_n, "synthetic": synth_n},
        "note": "636 empirical TP+FP disagreement cases plus 264 design-curated deceptive synthetics.",
        "cases": manifest_rows,
    }
    (staging / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    forbidden = _scan_java_forbidden(staging)
    if forbidden:
        raise SystemExit("Forbidden Java substrings found: " + "; ".join(forbidden[:20]))

    if in_place:
        borderline = empirical_dir
        if borderline.exists():
            shutil.rmtree(borderline)
        shutil.move(str(staging), str(borderline))
        _update_dataset_summary(manifest)
        return manifest

    if out_dir.exists():
        shutil.rmtree(out_dir)
    shutil.move(str(staging), str(out_dir))
    _update_dataset_summary(manifest)
    return manifest



def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--empirical-dir", type=Path, default=REPO_ROOT / "BenchmarkJava" / "borderline")
    ap.add_argument("--synthetic-pool", type=Path, default=REPO_ROOT / ".work" / "bl_synthetic_264")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "BenchmarkJava" / "borderline")
    ap.add_argument("--in-place", action="store_true")
    args = ap.parse_args()

    empirical_dir = args.empirical_dir.expanduser().resolve()
    synthetic_pool = args.synthetic_pool.expanduser().resolve()
    out_dir = args.out.expanduser().resolve()
    default_bl = (REPO_ROOT / "BenchmarkJava" / "borderline").resolve()
    in_place = args.in_place or out_dir == default_bl

    manifest = merge_borderline(
        empirical_dir=empirical_dir,
        synthetic_pool=synthetic_pool,
        out_dir=out_dir,
        in_place=in_place,
    )
    dest = default_bl if in_place else out_dir
    print(
        f"Merged {manifest['n_cases']} cases "
        f"(empirical={manifest['composition']['empirical']}, "
        f"synthetic={manifest['composition']['synthetic']}) -> {dest}"
    )


if __name__ == "__main__":
    main()
