#!/usr/bin/env python3
"""Select borderline cases from OWASP corpora with proven TP+FP model disagreement."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from lib.cwe_bucket import cwe_bucket  # noqa: E402
from lib.publish_case import publish_real_case  # noqa: E402
from lib.select_balanced import stratified_split  # noqa: E402

DEFAULT_PROFILES = ("qwen3_4b_bnb", "qwen3_8b_bnb", "qwen3_14b_bnb")
SEED = 42


def _load_label(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    lbl = str(data.get("label", "")).strip().upper()
    return lbl if lbl in {"TP", "FP", "BL", "UNKNOWN"} else None


def find_empirical_borderline(
    *,
    sast_root: Path,
    runs_root: Path,
    profiles: tuple[str, ...],
) -> list[dict]:
    rows: list[dict] = []
    for track in ("fp", "tp"):
        corpus = sast_root / "benchmark" / "corpora" / f"{track}_codeql"
        if not corpus.is_dir():
            corpus = sast_root / "benchmark" / f"{'rq1_codeql_only' if track == 'fp' else 'tp_codeql_only'}"
        for p in sorted(corpus.glob("*.json")):
            case = json.loads(p.read_text(encoding="utf-8"))
            cid = str(case.get("case_id") or p.stem)
            labels: dict[str, str] = {}
            for prof in profiles:
                rp = (
                    runs_root
                    / track
                    / "thinking_off"
                    / prof.replace("/", "_")
                    / "llm"
                    / cid
                    / "agent-llm-triage-result.json"
                )
                lbl = _load_label(rp)
                if lbl:
                    labels[prof] = lbl
            valid = [x for x in labels.values() if x in {"TP", "FP"}]
            if "TP" not in valid or "FP" not in valid:
                continue
            tp_rate = sum(1 for x in valid if x == "TP") / len(valid)
            rows.append(
                {
                    "case_id": cid,
                    "source_track": track,
                    "corpus_path": p,
                    "cwe_bucket": cwe_bucket(case),
                    "labels": labels,
                    "validation_tp_rate": round(tp_rate, 4),
                    "validation_disagreement": True,
                    "validation_tier": "empirical_tp_fp_split",
                    "ambiguity_score": round(1.0 - abs(tp_rate - 0.5) * 2, 4),
                }
            )
    rows.sort(key=lambda r: (-r["ambiguity_score"], r["case_id"]))
    return rows


def publish(
    *,
    rows: list[dict],
    bench_java: Path,
    out_root: Path,
    split_sizes: dict[str, int],
) -> None:
    n = sum(split_sizes.values())
    if len(rows) < n:
        raise SystemExit(f"Need {n} cases, found {len(rows)} empirical borderline cases")

    picked = rows[:n]
    splits = stratified_split(
        picked,
        train_n=split_sizes["train"],
        val_n=split_sizes["validation"],
        test_n=split_sizes["test"],
        seed=SEED,
    )

    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True)

    manifest_rows: list[dict] = []
    cwe_counts: Counter[str] = Counter()
    for split_name, entries in splits.items():
        for ent in entries:
            case = json.loads(ent["corpus_path"].read_text(encoding="utf-8"))
            extra = {
                "cwe_bucket": ent["cwe_bucket"],
                "split": split_name,
                "gold_track": "BL",
                "acceptable_labels": ["TP", "FP"],
                "synthetic": False,
                "synthetic_tier": None,
                "validation_tier": ent["validation_tier"],
                "validation_labels": ent["labels"],
                "validation_tp_rate": ent["validation_tp_rate"],
                "validation_disagreement": True,
                "source_track": ent["source_track"],
                "borderline_rationale": (
                    f"Empirical: models disagree TP vs FP on {ent['source_track']} track case."
                ),
            }
            row = publish_real_case(
                case_path=ent["corpus_path"],
                bench_java_root=bench_java,
                bundle_dir=out_root / split_name,
                gold_track="BL",
                extra=extra,
            )
            manifest_rows.append(row)
            cwe_counts[ent["cwe_bucket"]] += 1

    manifest = {
        "dataset": "benchmark_java_borderline_v2",
        "class": "borderline",
        "gold_track": "BL",
        "seed": SEED,
        "n_cases": n,
        "splits": split_sizes,
        "cwe_bucket_counts": dict(sorted(cwe_counts.items())),
        "selection": "empirical_model_tp_fp_disagreement",
        "validation_profiles": list(DEFAULT_PROFILES),
        "validation_tier": "empirical_tp_fp_split",
        "acceptable_labels": ["TP", "FP"],
        "self_contained": True,
        "cases": manifest_rows,
    }
    (out_root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=SCRIPTS_DIR.parent / "BenchmarkJava" / "borderline")
    ap.add_argument("--sast-root", type=Path, default=SCRIPTS_DIR.parent.parent / "SAST")
    ap.add_argument("--bench-java", type=Path, default=SCRIPTS_DIR.parent.parent / "BenchmarkJava")
    ap.add_argument("--runs-root", type=Path, default=SCRIPTS_DIR.parent.parent / "SAST" / "runs" / "phase1" / "stage2")
    ap.add_argument("-n", type=int, default=636)
    ap.add_argument("--train", type=int, default=353)
    ap.add_argument("--validation", type=int, default=141)
    ap.add_argument("--test", type=int, default=142)
    args = ap.parse_args()

    split_sizes = {
        "train": args.train,
        "validation": args.validation,
        "test": args.test,
    }
    if sum(split_sizes.values()) != args.n:
        raise SystemExit("train+validation+test must equal n")

    rows = find_empirical_borderline(
        sast_root=args.sast_root.resolve(),
        runs_root=args.runs_root.resolve(),
        profiles=DEFAULT_PROFILES,
    )
    print(f"Found {len(rows)} empirical TP+FP disagreement cases")
    publish(
        rows=rows,
        bench_java=args.bench_java.resolve(),
        out_root=args.out.resolve(),
        split_sizes=split_sizes,
    )
    print(f"Published {args.n} -> {args.out}")


if __name__ == "__main__":
    main()
