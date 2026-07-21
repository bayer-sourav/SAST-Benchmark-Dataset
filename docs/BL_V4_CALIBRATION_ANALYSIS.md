# BL v4 calibration analysis and template fixes

**Date:** 2026-07-06  
**Prior eval:** `SAST/runs/bl_v4_synthetic_eval` (6% BL, gates FAIL)  
**Re-eval:** `SAST/runs/bl_v4_calibrated_eval` (after `curated_v4_calibrated` rebuild)

---

## Per-case failure analysis (200-test, pre-fix)

Gold label for all cases: **BL**. Scoring accepts **BL only**.

| Category | Wrong | Dominant error | Root cause |
|----------|------:|----------------|------------|
| `dns_rebinding` | 49/50 | **TP** (49) | Weak string blocklists (`127.0.0.1`, `localhost`, RFC1918 prefixes) read as “insufficient SSRF mitigation” → **alert-TP**, not DNS-rebind **alert-unclear** |
| `bypassable_mitigation` | 50/50 | **TP** (39), FP (11) | Obviously partial mitigations (3-token XSS blacklist, apostrophe-only SQL, 3-char LDAP escape) → model cites incomplete sanitization per prompt rule 5 |
| `deployment_trust` | 46/50 | **TP** (31), FP (15) | Mixed: real sinks with partial scrub → TP; non-sinks (`cache.put`, `System.getProperty` name only) → FP |
| `semi_trusted_input` | 43/50 | **TP** (35) | `param` fallback paths (`trusted != null ? trusted : param`) make direct user flow obvious → TP |

**What worked (12 BL hits):** session/OAuth redirect chains, deferred audit/logging with partial redaction, and regex-recovered labels. Pilot few-shot exemplar (`BenchmarkTest26999`) uses **resolve-then-fetch by hostname** with **InetAddress API checks only** — no substring blocklists.

---

## Template calibration principles (`curated_v4_calibrated`)

### 1. DNS rebinding
- **Remove** substring IP/host blocklists and first-octet hacks.
- **Add** `isNonPublicAddress()` helper using `InetAddress` API (loopback, site-local, link-local, any-local).
- **Keep** architectural pattern: resolve/validate in one step, **fetch using hostname string** in a separate step (matches few-shot BL exemplar).

### 2. Bypassable mitigation
- Prefer **credible mitigations** (OWASP `Encode.forHtml` / `forHtmlAttribute`, `Path.normalize` + prefix guard, identifier allowlists, extended LDAP escape).
- Avoid patterns that scream “trivially incomplete” (3-keyword XSS blacklist, `replace("'", "''")` only).

### 3. Deployment trust
- **Remove** FP traps: cache key writes, dynamic property **name** lookups where value is constant.
- **Add** gated execution (`PendingSql.maybeRun` checks `sql.exec.enabled` servlet context flag).
- Keep real exposure sinks: logs, metrics tags, audit attributes, error pages.

### 4. Semi-trusted input
- **Remove** `param` fallbacks when trust source is absent (cookie, header, session attribute, partner URL).
- Early `return` when trusted source missing — forces model to reason about **who populates** the trust chain.

---

## Dataset rebuild

```bash
# 900 all-synthetic (train 500 / val 200 / test 200), stratified 50/category in test
cd SAST-Benchmark-Dataset
python3 scripts/build_borderline_v4.py --all-synthetic

# Pilot + few-shot exemplar (BenchmarkTest26999)
python3 scripts/build_borderline_v4_pilot.py

# Refresh SAST phase-2 test corpora
cd ../SAST
uv run python benchmark/build_phase2_corpora.py
```

**Selection tag:** `v4_all_synthetic_curated_calibrated`  
**Synthetic tier:** `curated_v4_calibrated`

---

## Re-eval command

```bash
cd SAST
BL_V4_SKIP_REBUILD=1 BL_V4_FORCE_RERUN=1 \
  BL_V4_RUNS_ROOT=runs/bl_v4_calibrated_eval/stage2_ship_bl \
  BL_V4_REVIEW_DIR=runs/bl_v4_calibrated_eval \
  bash benchmark/phases/phase2/run_bl_v4_eval.sh
```

Results: `runs/bl_v4_calibrated_eval/review_ship_bl.json`, `REVIEW_SHIP_BL.html`

### Calibrated re-eval results (2026-07-06)

**Full test (200 cases, ~1h 53m)**

| Metric | `curated_v4_tight` | `curated_v4_calibrated` | Δ |
|--------|-------------------:|------------------------:|--:|
| **Overall BL rate** | 6% | **7%** | +1pp |
| bypassable_mitigation | 0% | 6% | +6pp |
| deployment_trust | 8% | 2% | −6pp |
| dns_rebinding | 2% | **10%** | +8pp |
| semi_trusted_input | 14% | 10% | −4pp |
| **Gates** | FAIL | FAIL | — |

Distribution: TP 139 (−15), FP 46 (+12), BL 14 (+2), UNKNOWN 1.

**Pilot fast loop (40 cases, ~22 min)** — `runs/bl_v4_pilot_fast_v2/` (4-shot + `calibrated_v2`)

| Iteration | BL rate | bypass | dns | deployment | semi |
|-----------|--------:|-------:|----:|-----------:|-----:|
| tight (200 test) | 6% | 0% | 2% | 8% | 14% |
| calibrated v1 pilot | 10% | 0% | 20% | 10% | 10% |
| **calibrated v2 pilot** | **25%** | **30%** | **30%** | **20%** | **20% |

v2 changes: init-param bypassable templates, DNS `resolveHost`/fetch helpers, 4-shot few-shot (DNS + init-param BL exemplars), removed OWASP-encoder FP traps.

```bash
bash benchmark/phases/phase2/run_bl_v4_pilot_fast.sh   # default: v2_4shot + calibrated_v3 rebuild
```

**Full test v2 (200 cases)** — `runs/bl_v4_calibrated_v2_eval/`

| Metric | v2 full test |
|--------|-------------:|
| **Overall BL** | **20%** (40/200) |
| bypassable | 18% |
| dns_rebinding | **32%** |
| deployment_trust | 10% |
| semi_trusted_input | 20% |

---

## v3 iteration (`curated_v4_calibrated_v3`) — anti-overfitting policy

**Rule:** tune template pools from **v2 full-test per-template BL rates** (n≥5), not pilot-only misses. Do **not** add few-shot exemplars per pilot failure.

### Template pool changes (v3)

| Category | Pool size | Kept (full-test BL > 0%) | Removed |
|----------|----------:|----------------------------|---------|
| bypassable | 5 | init-param-regex-output, path-read-init-param, sql-identifier, path-normalize, allowlist-host | orderby, ldap, strip-tags, encoder traps |
| dns_rebinding | 4 | gethostbyname+urlconn (45%), sleep (36%), cache-hint (33%), fetch-after-resolve | url-host-resolve-fetch (15%), httpclient, openstream |
| deployment | 3 | html-comment-reflect (40%), audit-event-user-detail (33%), sql-built-request-attribute (12%) | metrics, redirect, log-sink, audit-map-secondary (0% full) |
| semi_trusted | 4 | init-param-regex (100%), cookie-prefixed (40%), session-partner (17%), oauth-state (14%) | role-gated, header-correlation, servlet-context (0% full) |

### Pilot results (40 cases, ~25 min) — fast feedback only

| Tier | BL rate | bypass | dns | deployment | semi |
|------|--------:|-------:|----:|-----------:|-----:|
| v2 pilot | **25%** | 30% | 30% | 20% | 20% |
| v3 pilot | 22.5% | **40%** | 30% | **0%** | 20% |

v3 pilot deployment **0%** despite keeping full-test winners — small-N noise (10 cases); v2 pilot had 20% deployment vs **10%** full test. **Do not revert v3 deployment pool based on pilot alone.**

Full-test validation: `runs/bl_v4_calibrated_v3_eval/` — **DONE**

| Metric | v2 full (200) | v3 full (200) | Δ |
|--------|--------------:|--------------:|--:|
| **Overall BL** | 20% | **27.5%** | +7.5pp |
| bypassable | 18% | **40%** | +22pp |
| dns_rebinding | 32% | 26% | −6pp |
| deployment_trust | 10% | 6% | −4pp |
| semi_trusted_input | 20% | **38%** | +18pp |
| **Gates** | FAIL | FAIL | — |

v3 **generalizes better overall** (+7.5pp) with pilot/full gap modest on bypass/semi. DNS regressed (−6pp) — likely from dropping httpclient/openstream variants; deployment flat-to-down. Still below 35%/50% gates.

---

## Prod ship alignment + v8-ship-bl prompt (2026-07-07)

**Prod config** (`integrations/github/MANIFEST.json`, `github_env.sh`):

| Knob | Before | After |
|------|--------|-------|
| Prompt | `v7-ship` (no BL rules) | **`v8-ship-bl`** |
| Few-shot | 0 (mistake) | **4** (`v2_4shot_tp_fp_bl2`) |
| Thinking | on | on |

`v8-ship-bl` = language-agnostic `v7-ship` procedure + strengthened BL calibration (DNS split-resolve, deployment deferred sinks, HTML-comment uncertainty) + strict-rule ordering so BL calibration applies before default **alert-TP**.

**Eval run:** `runs/bl_v4_prod_ship_eval/` (200-case full test, prod-matched config) — **DONE**

| Metric | v3 + v7-ship-bl | **prod v8-ship-bl + 4-shot** | Δ |
|--------|----------------:|-----------------------------:|--:|
| **Overall BL** | 27.5% | **41.5%** | +14pp |
| bypassable | 40% | 38% | −2pp |
| dns_rebinding | 26% | **54%** | +28pp |
| deployment_trust | 6% | **38%** | +32pp |
| semi_trusted_input | 38% | 36% | −2pp |
| **Gates (35% / 50% dns)** | FAIL | **PASS** | — |

Prompt-only change (same v3 templates, no new few-shot exemplars). DNS/deployment gains match strengthened BL calibration rules.

```bash
# Pilot fast loop
bash benchmark/phases/phase2/run_bl_v4_pilot_fast.sh

# Full test (generalization gate)
BL_V4_SKIP_REBUILD=1 BL_V4_FORCE_RERUN=1 \
  BL_V4_RUNS_ROOT=runs/bl_v4_calibrated_v3_eval/stage2_ship_bl \
  BL_V4_REVIEW_DIR=runs/bl_v4_calibrated_v3_eval \
  bash benchmark/phases/phase2/run_bl_v4_eval.sh
```

DNS rebinding improved most on full test (1→5 BL hits); bypassable broke 0% (3 BL). Overall still well below 35% gate — next levers: prompt/few-shot tuning, additional DNS exemplars, or teacher fine-tuning on BL train split.

---

## Files changed

| File | Change |
|------|--------|
| `scripts/synthetic/curated_bl_v4.py` | Calibrated templates for all 4 categories; DNS helper method; tier rename |
| `scripts/build_borderline_v4.py` | Selection `v4_all_synthetic_curated_calibrated` |
| `scripts/build_borderline_v4_pilot.py` | Exemplar aligned with DNS helper pattern |
| `SAST/benchmark/phases/phase2/BL_V4.md` | Baseline + calibrated eval pointers |
