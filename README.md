# SAST-Benchmark-Dataset

Static Application Security Testing (SAST) benchmark datasets for training and evaluating security triage models.

## BenchmarkJava (available)

| Class | Cases | Source | Gold |
|-------|-------|--------|------|
| `BenchmarkJava/fp/` | 900 | Real OWASP + CodeQL | FP |
| `BenchmarkJava/tp/` | 900 | Real OWASP + CodeQL | TP |
| `BenchmarkJava/borderline/` | 900 | 500 empirical OWASP (v4-tagged) + 400 curated synthetic | BL only (`acceptable_labels: ["BL"]`) |

Each class is **self-contained**: every case bundle includes `case.json` and Java source.

All three classes use splits **500 train / 200 validation / 200 test**.

See [BenchmarkJava/README.md](BenchmarkJava/README.md) for layout, case schema, and rebuild steps.

## Rebuild (summary)

**fp / tp** (requires sibling [SAST](https://github.com/) corpora and OWASP BenchmarkJava sources):

```bash
python3 scripts/build_java_dataset.py
```

**borderline v4** (principled categories; replaces v2/v3 model-disagreement selection):

```bash
python3 scripts/build_borderline_v4.py --dry-run   # preview composition
python3 scripts/build_borderline_v4.py --out BenchmarkJava/borderline
```

Spec: [docs/BORDERLINE_V4_SPEC.md](docs/BORDERLINE_V4_SPEC.md). Script reference: [scripts/README.md](scripts/README.md).

**Pilot** (40 all-synthetic smoke cases): `BenchmarkJava/borderline_pilot/` via `scripts/build_borderline_v4_pilot.py`.

## Planned

- `BenchmarkPython/`
- `BenchmarkNodeJS/`
