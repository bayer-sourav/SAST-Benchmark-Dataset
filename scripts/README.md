# Build scripts

Python utilities to rebuild [BenchmarkJava](../BenchmarkJava/) from upstream corpora and triage runs.

## Prerequisites

| Dependency | Path (default) | Used by |
|------------|----------------|---------|
| SAST corpora | `../SAST/benchmark/corpora/{fp,tp}_codeql` | `build_java_dataset.py` |
| OWASP sources | `../BenchmarkJava` | fp/tp/empirical publish |
| Stage 2 runs | `../SAST/runs/phase1/stage2/` | `build_empirical_borderline.py` |

## Published dataset

| Script | Output |
|--------|--------|
| `build_java_dataset.py` | `BenchmarkJava/fp/`, `BenchmarkJava/tp/` (900 each) |
| `build_empirical_borderline.py` | Staging: empirical borderline (636) |
| `build_bl_synthetic_264.py` | Staging: `.work/bl_synthetic_264/` (264) |
| `merge_borderline_900.py` | `BenchmarkJava/borderline/` (900, in-place merge) |

## Quick rebuild

```bash
# fp + tp only (does not touch borderline/ if DATASET_SUMMARY already has it)
python3 scripts/build_java_dataset.py

# borderline end-to-end
python3 scripts/build_empirical_borderline.py \
  -n 636 --train 353 --validation 141 --test 142 \
  --out .work/empirical_borderline_636

python3 scripts/build_bl_synthetic_264.py

python3 scripts/merge_borderline_900.py \
  --empirical-dir .work/empirical_borderline_636 \
  --synthetic-pool .work/bl_synthetic_264 \
  --in-place
```

## Layout

```
scripts/
├── build_java_dataset.py          # fp/tp from CodeQL corpora
├── build_empirical_borderline.py  # 636 model TP+FP disagreement cases
├── build_bl_synthetic_264.py      # publish curated synthetics to .work/
├── merge_borderline_900.py        # 636 + 264 → 900, stratified split
├── lib/
│   ├── cwe_bucket.py
│   ├── codeql_alert.py
│   ├── publish_case.py
│   └── select_balanced.py
└── synthetic/
    ├── generator_v2.py            # template engine (shared types/helpers)
    └── curated_bl_v3.py           # 264 design-curated BLSynthetic cases
```

## Staging (`.work/`)

Generated locally; not committed. Typical paths:

- `.work/empirical_borderline_636/` — empirical bundles before merge
- `.work/bl_synthetic_264/` — synthetic bundles before merge

Add `.work/` to your local gitignore (repo `.gitignore` includes it).

## Synthetic generation

`curated_bl_v3.py` defines 264 cases with deceptive patterns (wrong-variable sanitization, dead-branch escape, partial mitigations). Java sources use package `org.owasp.benchmark.testcode.blcurated` and contain **no** triage-hint comments.

`generator_v2.py` remains as the lower-level template/SARIF helper used by v3; it is not run directly for the published dataset.
