# BenchmarkJava — SAST CodeQL Dataset

Self-contained triage dataset for OWASP BenchmarkJava.

## Layout

```
BenchmarkJava/
├── fp/                 # 900 false-positive gold (real OWASP + CodeQL)
├── tp/                 # 900 true-positive gold (real OWASP + CodeQL)
├── borderline/         # 900 borderline v4 (500 empirical + 400 synthetic)
├── borderline_pilot/   # 40 all-synthetic pilot (10 per category)
└── DATASET_SUMMARY.json
```

Each class: `{class}/{split}/{case_id}/case.json` plus Java under `src/main/java/...`.

Splits for every class: **500 train / 200 validation / 200 test**.

## Gold labels

| Class | Gold | Meaning |
|-------|------|---------|
| `fp/` | FP | Dismiss alert (not a real vuln per OWASP) |
| `tp/` | TP | Keep alert (real vuln per OWASP) |
| `borderline/` | BL | Reviewer needs deployment/context before TP vs FP |
| `borderline_pilot/` | BL | Small synthetic-only pilot for prompt calibration |

For **borderline v4**, `acceptable_labels` is **`["BL"]` only** — models must output BL on BL-gold (TP/FP are errors). See [docs/BORDERLINE_V4_SPEC.md](../docs/BORDERLINE_V4_SPEC.md).

## fp / tp

- **900 each**, CWE-stratified natural sampling from CodeQL corpora (seed 42)
- Source: OWASP BenchmarkJava + CodeQL SARIF-aligned alerts
- Rebuild: `python3 scripts/build_java_dataset.py` (see [scripts/README.md](../scripts/README.md))

## Borderline v4 (published)

**Principle:** a competent reviewer needs **additional context** (deployment, reachability, mitigation bypass) before calling TP or FP.

**900 cases** — 500 empirical OWASP (pattern-tagged from fp/tp corpora) + 400 curated synthetic:

| Category | Role |
|----------|------|
| `bypassable_mitigation` | Sanitization stops naive attacks but skilled bypass exists |
| `dns_rebinding` | Resolve-then-fetch SSRF window (mostly synthetic) |
| `deployment_trust` | Impact depends on WAF/VPC/admin-only routing |
| `semi_trusted_input` | Session/config/partner data — not fully attacker-controlled |

| Tier | Count | IDs |
|------|-------|-----|
| Empirical | 500 | `BenchmarkTest*` |
| Synthetic | 400 | `BLv4*` |

Case fields: `borderline_version: "v4"`, `borderline_category`, `bl_context_questions`, `acceptable_labels: ["BL"]`.

### Pilot (`borderline_pilot/`)

40 all-synthetic cases (10 per category), IDs `BLv4p*`. Used to calibrate prompts before full eval.

### Manifest

`borderline/manifest.json` records v4 composition, category counts, and per-case split rows.

## Case bundle schema

Each `case.json` contains:

- CodeQL SARIF-shaped `raw_output` (alert location + rule)
- `case_id`, `gold_track`, `cwe_bucket`, `split` (in manifest rows)
- Class-specific metadata (see above)

## Rebuild borderline v4

Prerequisites: sibling `SAST/benchmark/corpora/{fp,tp}_codeql` and OWASP Java sources (monolithic `../BenchmarkJava` or per-case bundles under `fp/`/`tp/`).

```bash
python3 scripts/build_borderline_v4.py --dry-run
python3 scripts/build_borderline_v4.py --out BenchmarkJava/borderline
```

Pilot only:

```bash
python3 scripts/build_borderline_v4_pilot.py --out BenchmarkJava/borderline_pilot
```

Legacy v2/v3 rebuild scripts remain in `scripts/` for reference. Full reference: [scripts/README.md](../scripts/README.md).
