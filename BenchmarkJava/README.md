# BenchmarkJava — SAST CodeQL Dataset

Self-contained triage dataset for OWASP BenchmarkJava.

## Layout

```
BenchmarkJava/
├── fp/                 # 900 false-positive gold (real OWASP + CodeQL)
├── tp/                 # 900 true-positive gold (real OWASP + CodeQL)
├── borderline/         # 900 ambiguous cases (636 empirical + 264 synthetic)
└── DATASET_SUMMARY.json
```

Each class: `{class}/{split}/{case_id}/case.json` plus Java under `src/main/java/...`.

Splits for every class: **500 train / 200 validation / 200 test**.

## Gold labels

| Class | Gold | Meaning |
|-------|------|---------|
| `fp/` | FP | Dismiss alert (not a real vuln per OWASP) |
| `tp/` | TP | Keep alert (real vuln per OWASP) |
| `borderline/` | BL | **Both TP and FP are defensible** |

For borderline cases, `acceptable_labels` in `case.json` is **`["TP", "FP"]` only** (no BL label in the triage set).

## fp / tp

- **900 each**, CWE-stratified natural sampling from CodeQL corpora (seed 42)
- Source: OWASP BenchmarkJava + CodeQL SARIF-aligned alerts
- Rebuild: `python3 scripts/build_java_dataset.py` (see [scripts/README.md](../scripts/README.md))

## Borderline (published v2)

**900 cases** in two tiers:

| Tier | Count | IDs | Validation |
|------|-------|-----|------------|
| Empirical | 636 | `BenchmarkTest*` | Qwen3 4B/8B/14B all produced both TP and FP on the same alert (Phase 1 Stage 2) |
| Design-curated synthetic | 264 | `BLSynthetic*` | Deceptive partial-sanitization templates; no model gate |

### Empirical cases

- Real OWASP + CodeQL bundles
- `validation_tier: empirical_tp_fp_split`
- Fields: `validation_labels`, `validation_tp_rate`, `validation_profiles`

### Synthetic cases

- OWASP-style servlet sources; **no** label-leakage comments in Java
- `synthetic_tier: curated_v3_design`, `validation_tier: design_curated_no_model_gate`
- Fields: `template_id`, `tp_argument`, `fp_argument`, `borderline_rationale`

### Manifest

`borderline/manifest.json` records composition (`empirical_636_plus_curated_synthetic_264`), CWE counts, and per-case rows.

## Case bundle schema

Each `case.json` contains:

- CodeQL SARIF-shaped `raw_output` (alert location + rule)
- `case_id`, `gold_track`, `cwe_bucket`, `split` (in manifest rows)
- Class-specific metadata (see above)

## Rebuild borderline

Prerequisites: SAST repo with `runs/phase1/stage2/` triage outputs for fp/tp corpora.

```bash
# 1) Empirical 636 (staging directory)
python3 scripts/build_empirical_borderline.py \
  -n 636 --train 353 --validation 141 --test 142 \
  --out .work/empirical_borderline_636

# 2) Synthetic 264 pool
python3 scripts/build_bl_synthetic_264.py

# 3) Merge and publish 900 in-place (re-splits to 500/200/200)
python3 scripts/merge_borderline_900.py \
  --empirical-dir .work/empirical_borderline_636 \
  --synthetic-pool .work/bl_synthetic_264 \
  --in-place
```

Full script reference: [scripts/README.md](../scripts/README.md).

## Deprecated pipelines (removed)

Earlier repo versions included fully synthetic v1 borderline (900) and LLM-gated v2 pool validation. Those scripts are removed; the published tree matches **empirical + curated v3** only.
