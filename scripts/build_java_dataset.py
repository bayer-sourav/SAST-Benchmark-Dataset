#!/usr/bin/env python3
"""Build self-contained BenchmarkJava fp/ and tp/ classes (900 each).

Borderline (900) is built separately — see scripts/README.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from lib.cwe_bucket import cwe_bucket  # noqa: E402
from lib.publish_case import publish_real_case  # noqa: E402
from lib.select_balanced import select_balanced, stratified_split  # noqa: E402

SEED = 42
SPLIT_SIZES = {"train": 500, "validation": 200, "test": 200}
CLASS_TOTAL = 900


def build_real_class(
    *,
    name: str,
    corpus_dir: Path,
    bench_java: Path,
    out_root: Path,
    gold_track: str,
) -> dict:
    paths = sorted(corpus_dir.glob("*.json"))
    if len(paths) < CLASS_TOTAL:
        raise SystemExit(f"{name}: need {CLASS_TOTAL} cases, corpus has {len(paths)}")

    picked_paths = select_balanced(paths, n=CLASS_TOTAL, seed=SEED)
    pool = []
    for p in picked_paths:
        case = json.loads(p.read_text(encoding="utf-8"))
        cid = str(case.get("case_id") or p.stem.replace("OWASP_benchmark_java_", ""))
        pool.append(
            {
                "case_id": cid,
                "corpus_path": p,
                "cwe_bucket": cwe_bucket(case),
            }
        )

    splits = stratified_split(
        pool,
        train_n=SPLIT_SIZES["train"],
        val_n=SPLIT_SIZES["validation"],
        test_n=SPLIT_SIZES["test"],
        seed=SEED,
    )

    class_root = out_root / name
    if class_root.exists():
        import shutil

        shutil.rmtree(class_root)
    class_root.mkdir(parents=True)

    all_rows: list[dict] = []
    cwe_counts: Counter[str] = Counter()
    for split_name, entries in splits.items():
        for ent in entries:
            row = publish_real_case(
                case_path=ent["corpus_path"],
                bench_java_root=bench_java,
                bundle_dir=class_root / split_name,
                gold_track=gold_track,
                extra={"cwe_bucket": ent["cwe_bucket"], "split": split_name},
            )
            row["split"] = split_name
            all_rows.append(row)
            cwe_counts[ent["cwe_bucket"]] += 1

    manifest = {
        "dataset": f"benchmark_java_{name}_v1",
        "class": name,
        "gold_track": gold_track,
        "seed": SEED,
        "n_cases": CLASS_TOTAL,
        "splits": SPLIT_SIZES,
        "cwe_bucket_counts": dict(sorted(cwe_counts.items())),
        "selection": "cwe_stratified_natural_proportions",
        "self_contained": True,
        "bundle_layout": "{split}/{case_id}/case.json + {split}/{case_id}/{file}",
        "source_corpus": str(corpus_dir.resolve()),
        "cases": all_rows,
    }
    (class_root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return _manifest_summary(manifest)


def _manifest_summary(manifest: dict) -> dict:
    """Compact summary without per-case rows (see class manifest.json)."""
    skip = {"cases"}
    return {k: v for k, v in manifest.items() if k not in skip}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "BenchmarkJava",
    )
    ap.add_argument(
        "--sast-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent / "SAST",
    )
    ap.add_argument(
        "--bench-java",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent / "BenchmarkJava",
    )
    ap.add_argument("--skip-fp", action="store_true")
    ap.add_argument("--skip-tp", action="store_true")
    args = ap.parse_args()

    out_root = args.out.expanduser().resolve()
    sast = args.sast_root.expanduser().resolve()
    bench = args.bench_java.expanduser().resolve()

    fp_corpus = sast / "benchmark" / "corpora" / "fp_codeql"
    tp_corpus = sast / "benchmark" / "corpora" / "tp_codeql"
    if not fp_corpus.is_dir():
        fp_corpus = sast / "benchmark" / "rq1_codeql_only"
    if not tp_corpus.is_dir():
        tp_corpus = sast / "benchmark" / "tp_codeql_only"

    out_root.mkdir(parents=True, exist_ok=True)
    summary: dict = {"out_root": str(out_root), "classes": {}}

    if not args.skip_fp:
        if not fp_corpus.is_dir():
            raise SystemExit(f"Missing FP corpus: {fp_corpus}")
        summary["classes"]["fp"] = build_real_class(
            name="fp",
            corpus_dir=fp_corpus,
            bench_java=bench,
            out_root=out_root,
            gold_track="FP",
        )
        print(f"fp: {summary['classes']['fp']['n_cases']} cases")

    if not args.skip_tp:
        if not tp_corpus.is_dir():
            raise SystemExit(f"Missing TP corpus: {tp_corpus}")
        summary["classes"]["tp"] = build_real_class(
            name="tp",
            corpus_dir=tp_corpus,
            bench_java=bench,
            out_root=out_root,
            gold_track="TP",
        )
        print(f"tp: {summary['classes']['tp']['n_cases']} cases")

    summary_path = out_root / "DATASET_SUMMARY.json"
    if summary_path.is_file():
        existing = json.loads(summary_path.read_text(encoding="utf-8"))
        if "borderline" in existing.get("classes", {}):
            summary.setdefault("classes", {})["borderline"] = existing["classes"]["borderline"]
    (summary_path).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote {out_root / 'DATASET_SUMMARY.json'}")


if __name__ == "__main__":
    main()
