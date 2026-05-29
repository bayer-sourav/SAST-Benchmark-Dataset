# SAST-Benchmark-Dataset

Static Application Security Testing (SAST) benchmark datasets for training and evaluating security triage models.

## BenchmarkJava (available)

| Class | Cases | Source | Gold |
|-------|-------|--------|------|
| `BenchmarkJava/fp/` | 900 | Real OWASP + CodeQL | FP |
| `BenchmarkJava/tp/` | 900 | Real OWASP + CodeQL | TP |
| `BenchmarkJava/borderline/` | 900 | 636 empirical OWASP + 264 design-curated synthetic | BL (TP and FP both acceptable) |

Each class is **self-contained**: every case bundle includes `case.json` and Java source.

All three classes use splits **500 train / 200 validation / 200 test**.

See [BenchmarkJava/README.md](BenchmarkJava/README.md) for layout, case schema, and rebuild steps.

## Rebuild (summary)

**fp / tp** (requires sibling [SAST](https://github.com/) corpora and OWASP BenchmarkJava sources):

```bash
python3 scripts/build_java_dataset.py
```

**borderline** (three-step pipeline; empirical half needs Phase 1 Stage 2 LLM runs):

```bash
python3 scripts/build_empirical_borderline.py -n 636 ...
python3 scripts/build_bl_synthetic_264.py
python3 scripts/merge_borderline_900.py --in-place
```

Details: [scripts/README.md](scripts/README.md).

## Planned

- `BenchmarkPython/`
- `BenchmarkNodeJS/`
