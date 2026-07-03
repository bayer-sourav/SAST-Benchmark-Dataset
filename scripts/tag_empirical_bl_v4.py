"""Tag OWASP cases from fp/tp corpora against borderline v4 categories."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from lib.bl_categories import CATEGORIES, CATEGORY_LABELS  # noqa: E402
from lib.cwe_bucket import cwe_bucket  # noqa: E402
from lib.java_source import resolve_java_source  # noqa: E402

# --- Category 1: bypassable mitigation heuristics ---
_CAT1_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "substring_allowlist",
        re.compile(r"\.contains\s*\(\s*[\"']", re.I),
        "Substring allowlist check on user-influenced string.",
    ),
    (
        "starts_with_scheme",
        re.compile(r"\.startsWith\s*\(\s*[\"']https?://", re.I),
        "Scheme prefix check bypassable via embedded scheme tricks.",
    ),
    (
        "blacklist_replace",
        re.compile(r"\.replace(All)?\s*\(\s*[\"'][^\"']*(script|select|union|<)[^\"']*[\"']", re.I),
        "Blacklist-style replace/filter on tainted data.",
    ),
    (
        "html_escape_js_sink",
        re.compile(r"HtmlUtils\.htmlEscape|encodeForHTML", re.I),
        "HTML encoder present; sink context may differ (JS/HTML mismatch).",
    ),
    (
        "partial_private_ip_block",
        re.compile(r"127\.0\.0\.1", re.I),
        "Blocks 127.0.0.1 only; other local representations may remain.",
    ),
    (
        "url_decode_before_check",
        re.compile(r"URLDecoder\.decode|decode\s*\(", re.I),
        "Decode before validation enables encoding bypass.",
    ),
]

# --- Category 2: DNS rebinding (rare in OWASP) ---
_CAT2_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "resolve_then_fetch",
        re.compile(
            r"InetAddress\.getByName[\s\S]{0,800}(openConnection|HttpURLConnection|HttpClient|\.get\s*\()",
            re.I,
        ),
        "Hostname resolved separately from outbound request (rebind window).",
    ),
]

# --- Category 3: deployment trust (weak auto-tag; prefer synthetic) ---
_CAT3_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "logging_sink",
        re.compile(r"\.(log|info|debug|warn|error)\s*\(", re.I),
        "Sink is logging; impact depends on log exposure and retention.",
    ),
    (
        "admin_path_hint",
        re.compile(r"@WebServlet\s*\(\s*value\s*=\s*[\"'][^\"']*(admin|internal|mgmt)", re.I),
        "Admin/internal route; reachability not visible in snippet.",
    ),
]

# --- Category 4: semi-trusted input ---
_CAT4_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "session_attribute",
        re.compile(r"getSession\s*\(\s*\)\s*\.getAttribute", re.I),
        "Data from session attribute set earlier in flow.",
    ),
    (
        "init_parameter",
        re.compile(r"getInitParameter\s*\(|getServletContext\s*\(\s*\)\.getInitParameter", re.I),
        "Servlet init/config parameter — typically admin-set.",
    ),
    (
        "cookie_non_request",
        re.compile(r"getCookies\s*\(\s*\)|getValue\s*\(\s*[\"']", re.I),
        "Cookie value; may be server-set or prior response.",
    ),
]


def _match_category(text: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for cat, patterns in (
        ("bypassable_mitigation", _CAT1_PATTERNS),
        ("dns_rebinding", _CAT2_PATTERNS),
        ("deployment_trust", _CAT3_PATTERNS),
        ("semi_trusted_input", _CAT4_PATTERNS),
    ):
        for tag, pat, rationale in patterns:
            if pat.search(text):
                hits.append(
                    {
                        "borderline_category": cat,
                        "pattern_tag": tag,
                        "pattern_rationale": rationale,
                    }
                )
    return hits


def tag_case(case: dict[str, Any], java_text: str) -> dict[str, Any] | None:
    hits = _match_category(java_text)
    if not hits:
        return None
    # Prefer cat1 > cat2 > cat4 > cat3 when multiple match
    priority = {c: i for i, c in enumerate(CATEGORIES)}
    hits.sort(key=lambda h: priority[h["borderline_category"]])
    primary = hits[0]
    cat = primary["borderline_category"]
    return {
        "case_id": case.get("case_id"),
        "cwe_bucket": cwe_bucket(case),
        "borderline_category": cat,
        "borderline_category_label": CATEGORY_LABELS[cat],
        "pattern_tag": primary["pattern_tag"],
        "borderline_rationale": primary["pattern_rationale"],
        "all_hits": hits,
        "source_track_hint": case.get("_eval_gold_track") or case.get("gold_track"),
    }


def scan_corpora(*, sast_root: Path, bench_java: Path) -> list[dict[str, Any]]:
    tagged: list[dict[str, Any]] = []
    for track in ("fp", "tp"):
        for corpus_name in (f"{track}_codeql", f"phase2_{track}_test"):
            corpus = sast_root / "benchmark" / "corpora" / corpus_name
            if not corpus.is_dir():
                corpus = sast_root / "benchmark" / ("rq1_codeql_only" if track == "fp" else "tp_codeql_only")
            if not corpus.is_dir():
                continue
            for p in sorted(corpus.glob("*.json")):
                case = json.loads(p.read_text(encoding="utf-8"))
                java_path = resolve_java_source(case, dataset_java_root=bench_java)
                if java_path is None:
                    continue
                java_text = java_path.read_text(encoding="utf-8", errors="replace")
                row = tag_case(case, java_text)
                if row:
                    row["corpus_path"] = str(p)
                    row["source_track"] = track
                    tagged.append(row)
    # dedupe by case_id
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for row in tagged:
        cid = row["case_id"]
        if cid in seen:
            continue
        seen.add(cid)
        unique.append(row)
    return unique


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sast-root", type=Path, default=SCRIPTS_DIR.parent.parent / "SAST")
    ap.add_argument("--bench-java", type=Path, default=SCRIPTS_DIR.parent / "BenchmarkJava")
    ap.add_argument("--report", type=Path, required=True)
    args = ap.parse_args()

    rows = scan_corpora(sast_root=args.sast_root.resolve(), bench_java=args.bench_java.resolve())
    from collections import Counter

    by_cat = Counter(r["borderline_category"] for r in rows)
    report = {
        "n_tagged": len(rows),
        "by_category": dict(sorted(by_cat.items())),
        "cases": rows,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"n_tagged": len(rows), "by_category": report["by_category"]}, indent=2))


if __name__ == "__main__":
    main()
