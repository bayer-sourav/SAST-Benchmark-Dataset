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
| `build_empirical_borderline.py` | **Legacy v2/v3** staging: empirical borderline (636) |
| `build_bl_synthetic_264.py` | **Legacy v2/v3** staging: `.work/bl_synthetic_264/` (264) |
| `merge_borderline_900.py` | **Legacy v2/v3** `BenchmarkJava/borderline/` (900) |
| `tag_empirical_bl_v4.py` | Tag OWASP fp/tp cases by v4 principled categories |
| `build_bl_synthetic_v4.py` | Publish 400 v4 synthetic cases |
| `build_borderline_v4.py` | **v4** `BenchmarkJava/borderline/` (500 empirical + 400 synthetic) |

See [docs/BORDERLINE_V4_SPEC.md](../docs/BORDERLINE_V4_SPEC.md) for the v4 definition (replaces model-disagreement selection).

## Quick rebuild (v4 borderline — recommended)

```bash
# Preview composition
python3 scripts/build_borderline_v4.py --dry-run

# Full rebuild (replaces BenchmarkJava/borderline/)
python3 scripts/build_borderline_v4.py --out BenchmarkJava/borderline
```

Requires sibling `SAST/` corpora and `BenchmarkJava/` OWASP sources.

## Legacy rebuild (v2/v3)

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
├── build_borderline_v4.py         # v4: 500 empirical + 400 synthetic → borderline/
├── build_borderline_v4_pilot.py   # 40-case all-synthetic pilot
├── build_bl_synthetic_v4.py       # publish synthetic pool only
├── tag_empirical_bl_v4.py         # tag OWASP fp/tp by v4 categories
├── build_empirical_borderline.py  # legacy v2/v3 empirical
├── build_bl_synthetic_264.py      # legacy v2/v3 synthetics
├── merge_borderline_900.py        # legacy v2/v3 merge
├── lib/
│   ├── bl_categories.py           # v4 category enums + acceptable_labels
│   ├── java_source.py             # resolve Java path (bundle / mono OWASP)
│   ├── cwe_bucket.py
│   ├── codeql_alert.py
│   ├── publish_case.py
│   └── select_balanced.py
└── synthetic/
    ├── curated_bl_v4.py           # 400 v4 synthetic templates (BLv4#####)
    ├── curated_bl_v3.py           # legacy 264 BLSynthetic cases
    └── generator_v2.py            # lower-level template helpers
```

## Staging (`.work/`)

Generated locally; not committed. Typical paths:

- `.work/empirical_borderline_636/` — empirical bundles before merge
- `.work/bl_synthetic_264/` — synthetic bundles before merge

Add `.work/` to your local gitignore (repo `.gitignore` includes it).

## Synthetic generation

**v4** (`curated_bl_v4.py`): 400 cases across four principled categories; IDs `BLv4#####`, package `org.owasp.benchmark.testcode.blv4`. No triage-hint comments in Java.

**Legacy v3** (`curated_bl_v3.py`): 264 deceptive-pattern cases (`BLSynthetic*`). Superseded by v4 for borderline rebuilds.

`generator_v2.py` remains as the lower-level template/SARIF helper; not run directly for the published v4 dataset.
