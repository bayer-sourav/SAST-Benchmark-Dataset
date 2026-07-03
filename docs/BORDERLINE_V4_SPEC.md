# Borderline (BL) v4 — design specification

**Status:** Draft (replaces v2/v3 empirical + synthetic borderline)  
**Principle:** A real security engineer would need **additional context** before making a call.

When annotators disagree (TP vs BL, FP vs BL), resolve to **BL**. The class captures the uncertainty zone — not a disguised hard TP or tricky FP.

---

## Why v2/v3 failed in triage eval

| Issue | v2/v3 approach | Effect on models |
|-------|----------------|------------------|
| **Selection criterion** | 636 cases = LLM **TP+FP disagreement** on FP/TP tracks | Hard/ambiguous for *models*, not necessarily borderline for *humans* |
| **Synthetic patterns** | Dead-branch sanitization, wrong-variable escape | Teaches "find the trick" → models pick TP or FP decisively |
| **Scoring** | `acceptable_labels: ["TP", "FP"]` only | **BL output never rewarded**; Stage 2/3C predict 0% BL on BL-gold |
| **Teacher supervision** | 85% of BL-train labeled TP by Stage 2 teacher | Contradictory signal; BL train blurs TP/FP boundary without teaching BL |

**Observed:** ~87% of BL-gold test cases predicted as **TP**, ~13% as **FP**, ~0% as **BL**.

---

## v4 overarching rule

> If a competent reviewer, seeing only the code + alert, would say *"I need to know how this is deployed / who can reach it / whether that mitigation is bypassable in practice"* before dismissing or escalating — the case is **BL**.

---

## Four qualifying categories

### 1. `bypassable_mitigation`

Sanitization or validation would stop a **naive** attacker, but a **skilled** attacker has a realistic bypass:

- Substring allowlist (`safe.com` in hostname → `evil.safe.com`)
- `startsWith("https://")` → `https://evil.https://safe.com`
- Blocking only some private IP forms (`127.0.0.1` but not `localhost`, `0.0.0.0`, `::1`)
- URL-encoding applied before validation
- Blacklist XSS filters, HTML-escape in JS context, partial SQL escaping

**Not BL:** trivially bypassable with arbitrary input and no mitigation effort (that's **TP**).

### 2. `dns_rebinding`

Code resolves a hostname to validate (e.g. block private IPs), then performs the HTTP request **separately**. A DNS rebind between those steps can reach internal targets.

**Requires:** resolve + fetch pattern (often SSRF-shaped). OWASP BenchmarkJava has **no** native DNS-rebinding cases → **synthetic-only** for this bucket.

### 3. `deployment_trust`

Exploitability depends on facts **not visible in code**:

- WAF / network ACL in front of the app?
- Admin-only route or internal VPC only?
- Does the backend behind the URL perform sensitive actions?

Document required context in `bl_context_questions[]` on the case JSON.

### 4. `semi_trusted_input`

Input is not fully attacker-controlled under normal assumptions:

- Admin-configured settings (high privilege to set)
- Partner / OAuth API response (trusted third party; compromise enables abuse)
- Session attribute set earlier in the flow

---

## Case JSON schema (v4 additions)

```json
{
  "gold_track": "BL",
  "acceptable_labels": ["BL"],
  "borderline_version": "v4",
  "borderline_category": "bypassable_mitigation",
  "borderline_rationale": "Human-readable one-liner",
  "bl_argument": "Why a reviewer must pause for context",
  "tp_argument": "What would push a reviewer to TP",
  "fp_argument": "What would push a reviewer to FP",
  "bl_context_questions": ["Is there a WAF?", "..."],
  "dispute_resolution": "TP|FP disagreement → BL"
}
```

### Scoring change (SAST benchmark)

| Field | v2/v3 | v4 |
|-------|-------|-----|
| `acceptable_labels` | `["TP", "FP"]` | `["BL"]` (TP/FP count as **errors** on BL-gold) |
| BL lenient accuracy | TP or FP = correct | **BL only** = correct |
| Prompt | Case-level TP/FP/BL rules | Explicit BL when context missing |

This aligns training and eval with the intended output class.

---

## Dataset composition target (900 cases)

| Source | Count | Categories |
|--------|------:|------------|
| OWASP empirical (tagged) | ~500 | Mostly cat 1 + 4; some cat 3 |
| Synthetic curated v4 | ~400 | All cats; **required** for cat 2 + most cat 3 |

Splits unchanged: **500 train / 200 validation / 200 test**, stratified by `borderline_category` × `cwe_bucket`.

---

## Rebuild pipeline

```bash
# 1. Tag OWASP fp/tp corpora → empirical BL candidates
python3 scripts/tag_empirical_bl_v4.py --report .work/bl_v4_empirical_pool.json

# 2. Generate synthetic v4 pool (all 4 categories)
python3 scripts/build_bl_synthetic_v4.py --out .work/bl_synthetic_v4

# 3. Merge, stratify, publish 900
python3 scripts/build_borderline_v4.py --out BenchmarkJava/borderline
```

---

## Category → CWE mapping (Java / CodeQL)

| Category | Example ruleIds | OWASP coverage |
|----------|-----------------|----------------|
| bypassable_mitigation | xss, sql-injection, path-injection, ldapi | **Strong** |
| dns_rebinding | ssrf / url-fetch (synthetic) | **None** |
| deployment_trust | xss, sql-injection, error-message | **Weak** — synthetic + manual |
| semi_trusted_input | xss, sql-injection, path-injection | **Moderate** (session/config patterns) |

---

## Migration notes

1. Rebuild `SAST/benchmark/corpora/phase2_bl_*` from new `BenchmarkJava/borderline/test|validation|train`.
2. Update `build_phase2_corpora.py` if case schema fields change.
3. Update triage prompt (`v7-ship` / balanced) to **require BL** when context questions are unanswered.
4. Re-run Phase 2 eval — expect lower BL accuracy initially (desired signal).

## Phase 2 eval (SAST repo)

See `SAST/benchmark/phases/phase2/BL_V4.md` for pilot/full eval scripts, prompt config, and baseline results.
