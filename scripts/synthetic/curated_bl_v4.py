"""Borderline v4 synthetic cases — principled BL categories (pilot + full pool)."""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from typing import Any, Callable

from lib.bl_categories import BL_V4_ACCEPTABLE_LABELS, BL_V4_VERSION, CATEGORY_LABELS
from lib.codeql_alert import make_alert, wrap_codeql

JAVA_PKG = "org.owasp.benchmark.testcode"
REL_PREFIX = f"src/main/java/{JAVA_PKG.replace('.', '/')}"

# OWASP-style IDs (no BL/blv4 in filenames or packages — avoids label leakage in prompts)
PILOT_ID_OFFSET = 27_000       # BenchmarkTest27001–27040 (pilot)
SYNTHETIC_ID_OFFSET = 28_000   # BenchmarkTest28001–28900 (full pool)
FEWSHOT_EXEMPLAR_ID = "BenchmarkTest26999"
FEWSHOT_EXEMPLAR_INIT_PARAM_ID = "BenchmarkTest26998"

FORBIDDEN = (
    "Synthetic",
    "SINK:",
    "borderline",
    "BL v4 hint",
    "blv4",
    "BlV4",
    "BLv4",
    "BLv",
    "blcurated",
    "BLSynthetic",
)


@dataclass
class BlV4Case:
    case_id: str
    borderline_category: str
    cwe_bucket: str
    java_source: str
    rel_file: str
    sink_line: int
    rule_id: str
    message: str
    template_id: str
    borderline_rationale: str
    bl_argument: str
    tp_argument: str
    fp_argument: str
    bl_context_questions: list[str]


_CWE_SERVLET_FAMILY: dict[str, str] = {
    "xss": "xss",
    "sql-injection": "sqli",
    "path-injection": "pathtraver",
    "ldapi": "ldapi",
    "error-message-exposure": "trustbound",
    "ssrf": "pathtraver",
}


def owasp_case_id(seq: int, *, pilot: bool = False) -> str:
    base = PILOT_ID_OFFSET if pilot else SYNTHETIC_ID_OFFSET
    return f"BenchmarkTest{base + seq:05d}"


def servlet_route(cwe: str, case_id: str, variant: int) -> str:
    """Match OWASP BenchmarkJava servlet paths, e.g. /xss-00/BenchmarkTest00100."""
    family = _CWE_SERVLET_FAMILY.get(cwe, "xss")
    tier = variant % 5
    return f"/{family}-{tier:02d}/{case_id}"


def _header(class_name: str, servlet_route_path: str, *, class_helpers: str = "") -> str:
    helpers = ""
    if class_helpers.strip():
        helpers = "\n" + textwrap.indent(class_helpers.strip(), "    ") + "\n"
    return textwrap.dedent(
        f"""
        package {JAVA_PKG};

        import java.io.IOException;
        import javax.servlet.ServletException;
        import javax.servlet.annotation.WebServlet;
        import javax.servlet.http.HttpServlet;
        import javax.servlet.http.HttpServletRequest;
        import javax.servlet.http.HttpServletResponse;

        @WebServlet(value = "{servlet_route_path}")
        public class {class_name} extends HttpServlet {{
            private static final long serialVersionUID = 1L;
        {helpers}
            @Override
            protected void doPost(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {{
                response.setContentType("text/html;charset=UTF-8");
                String param = request.getParameter("BenchmarkTest");
                if (param == null) param = "";
        """
    ).strip()


def _footer() -> str:
    return "\n    }\n}\n"


_DNS_ADDRESS_HELPERS = """
private static boolean isNonPublicAddress(java.net.InetAddress addr) {
    return addr.isLoopbackAddress() || addr.isSiteLocalAddress()
            || addr.isLinkLocalAddress() || addr.isAnyLocalAddress();
}

private static java.net.InetAddress resolveHost(String host) throws java.net.UnknownHostException {
    return java.net.InetAddress.getByName(host);
}
"""


def _assemble(
    class_name: str,
    servlet_route_path: str,
    body: str,
    *,
    class_helpers: str = "",
) -> tuple[str, int]:
    header = _header(class_name, servlet_route_path, class_helpers=class_helpers)
    body = textwrap.dedent(body).strip("\n")
    sink_line: int | None = None
    out_lines: list[str] = []
    for line in body.split("\n"):
        if "@sink" in line:
            sink_line = header.count("\n") + 1 + len(out_lines) + 1
            line = line.replace("@sink", "").rstrip()
            if line.strip():
                out_lines.append(line)
        else:
            out_lines.append(line)
    if sink_line is None:
        raise ValueError("missing @sink")
    return header + "\n" + "\n".join(out_lines) + _footer(), sink_line


def _assert_no_leak(text: str, *, case_id: str) -> None:
    low = text.lower()
    for bad in FORBIDDEN:
        if bad.lower() in low:
            raise ValueError(f"{case_id} leaks forbidden substring {bad!r}")


def _mk(
    seq: int,
    *,
    pilot: bool,
    variant: int,
    category: str,
    cwe: str,
    rule: str,
    tpl: str,
    body: str,
    message: str,
    bl: str,
    tp: str,
    fp: str,
    qs: list[str],
    class_helpers: str = "",
) -> BlV4Case:
    cid = owasp_case_id(seq, pilot=pilot)
    route = servlet_route(cwe, cid, variant)
    java, sink = _assemble(cid, route, body, class_helpers=class_helpers)
    _assert_no_leak(java, case_id=cid)
    return BlV4Case(
        case_id=cid,
        borderline_category=category,
        cwe_bucket=cwe,
        java_source=java,
        rel_file=f"{REL_PREFIX}/{cid}.java",
        sink_line=sink,
        rule_id=rule,
        message=message,
        template_id=tpl,
        borderline_rationale=CATEGORY_LABELS[category],  # type: ignore[index]
        bl_argument=bl,
        tp_argument=tp,
        fp_argument=fp,
        bl_context_questions=qs,
    )


# --- v3: template pools tuned on FULL-TEST generalization (not pilot-only) ---

def _gen_bypassable(seq: int, variant: int, *, pilot: bool = False) -> BlV4Case:
    """Bypassable: deploy-time guards + identifier/path patterns with full-test BL signal."""
    templates = [
        (
            "init-param-regex-output",
            "java/xss",
            "xss",
            """
            String pat = getServletContext().getInitParameter("safe.pattern");
            if (pat != null && param.matches(pat)) {
                response.getWriter().println(param); @sink
            }
            """,
            "Output gated by deploy-time regex init parameter.",
            "Init params are admin-controlled; regex strength and change control determine TP vs acceptable policy.",
            "Weak regex from admin misconfig allows XSS.",
            "Regex reviewed in change-managed deployment manifest.",
            ["Who can change init params?", "Was regex red-teamed?"],
        ),
        (
            "allowlist-host-only-path-user",
            "java/path-injection",
            "path-injection",
            """
            String host = param;
            String seg = request.getParameter("seg");
            if (seg == null) seg = "home";
            if (host.matches("^[a-zA-Z0-9.-]+\\\\.safe\\\\.com$")) {
                response.sendRedirect("https://" + host + "/" + seg); @sink
            }
            """,
            "Redirect with strict host regex but user-controlled path segment.",
            "Host allowlist does not constrain path segment; open-redirect severity depends on partner trust and redirect policy.",
            "Path segment enables phishing or SSRF chaining despite host regex.",
            "Path values come from signed server token in production.",
            ["Who supplies seg?", "Are off-domain redirects blocked downstream?"],
        ),
        (
            "path-normalize-single-decode",
            "java/path-injection",
            "path-injection",
            """
            String once = java.net.URLDecoder.decode(param, "UTF-8");
            java.nio.file.Path base = java.nio.file.Paths.get("/data").toAbsolutePath().normalize();
            java.nio.file.Path resolved = base.resolve(once).normalize();
            if (resolved.startsWith(base)) {
                java.nio.file.Files.readAllBytes(resolved); @sink
                response.getWriter().println("ok");
            }
            """,
            "Normalized path join under /data after single URL decode.",
            "Single decode plus normalize may miss double-encoding; sensitivity of /data and symlink layout unknown.",
            "Encoding tricks or symlinks escape intended jail.",
            "/data is public read-only static content on this host.",
            ["What lives under /data/?", "Is path normalized again before open()?"],
        ),
        (
            "sql-identifier-allowlist",
            "java/sql-injection",
            "sql-injection",
            """
            if (param.matches("^[a-zA-Z][a-zA-Z0-9_]*$")) {
                String sql = "SELECT * FROM " + param + " WHERE active=1";
                java.sql.Connection con = (java.sql.Connection) request.getAttribute("dbConn");
                if (con != null) {
                    java.sql.Statement st = con.createStatement();
                    st.executeQuery(sql); @sink
                }
            }
            """,
            "Dynamic table name with alphanumeric identifier allowlist.",
            "Identifier allowlist limits shape but DB role, quoting, and dialect-specific vectors need deployment context.",
            "Alternate identifiers or stacked queries bypass allowlist on privileged DB.",
            "Read-only replica plus WAF on SQL shapes blocks abuse.",
            ["Which DB and privileges?", "Is dbConn always non-null in prod?"],
        ),
        (
            "path-read-init-param-pattern",
            "java/path-injection",
            "path-injection",
            """
            String pat = getServletContext().getInitParameter("file.pattern");
            if (pat != null && param.matches(pat)) {
                java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/data/" + param)); @sink
                response.getWriter().println("ok");
            }
            """,
            "File read when filename matches deploy-time pattern init parameter.",
            "Pattern strength and /data sensitivity are environmental — guard blocks naive traversal only.",
            "Regex bypass or symlink under /data escapes jail.",
            "/data is static public content with no symlinks.",
            ["Who sets file.pattern?", "What is stored under /data/?"],
        ),
    ]
    tpl, rule, cwe, body, msg, bl, tp, fp, qs = templates[variant % len(templates)]
    return _mk(seq, pilot=pilot, variant=variant, category="bypassable_mitigation", cwe=cwe, rule=rule, tpl=tpl,
               body=body, message=msg, bl=bl, tp=tp, fp=fp, qs=qs)


def _gen_dns_rebinding(seq: int, variant: int, *, pilot: bool = False) -> BlV4Case:
    """DNS rebinding: resolveHost() then fetch by hostname — drop full-URL fetch variants (15% BL on full test)."""
    _fetch_helpers = """
private void fetchHttpByHostname(String host) throws java.io.IOException {
    new java.net.URL("http://" + host + "/api").openStream();
}

private void connectHttpByHostname(String host) throws java.io.IOException {
    new java.net.URL("http://" + host).openConnection().connect();
}

private void openUrlByHostname(String host) throws java.io.IOException {
    new java.net.URL("https://" + host + "/health").openStream();
}
"""
    variants = [
        (
            "dns-rebind-gethostbyname-then-urlconn",
            """
            String host = param;
            if (isNonPublicAddress(resolveHost(host))) return;
            java.net.URLConnection c = new java.net.URL("http://" + host + "/v1").openConnection(); @sink
            c.connect();
            """,
            "resolveHost validation, URLConnection constructed with hostname string.",
        ),
        (
            "dns-rebind-sleep-between",
            """
            String host = param;
            if (isNonPublicAddress(resolveHost(host))) return;
            Thread.sleep(50);
            connectHttpByHostname(host); @sink
            """,
            "resolveHost, delay, connectHttpByHostname by name.",
        ),
        (
            "dns-rebind-cache-hint-then-fetch",
            """
            String host = param;
            java.net.InetAddress addr = resolveHost(host);
            if (isNonPublicAddress(addr)) return;
            addr.getHostName();
            openUrlByHostname(host); @sink
            """,
            "resolveHost, cache warm, openUrlByHostname.",
        ),
        (
            "dns-rebind-fetch-after-resolve",
            """
            String host = param;
            if (isNonPublicAddress(resolveHost(host))) return;
            fetchHttpByHostname(host); @sink
            """,
            "resolveHost then fetchHttpByHostname — separate resolve and fetch steps.",
        ),
    ]
    tpl, body, _ = variants[variant % len(variants)]
    return _mk(
        seq,
        pilot=pilot,
        variant=variant,
        category="dns_rebinding",
        cwe="ssrf",
        rule="java/ssrf",
        tpl=tpl,
        body=body,
        message="Separate DNS resolution and outbound fetch.",
        bl="Resolve-then-fetch uses different steps; rebinding impact depends on TTL, cache, and egress — cannot rule TP/FP from snippet alone.",
        tp="Timed DNS flip between resolve and fetch could reach internal targets.",
        fp="Same-connection fetch, short TTL denylist, or egress ACL may neutralize the window.",
        qs=["DNS TTL for allowed names?", "Same TCP connection for resolve and fetch?", "Egress deny RFC1918/metadata?"],
        class_helpers=_DNS_ADDRESS_HELPERS + _fetch_helpers,
    )


def _gen_deployment_trust(seq: int, variant: int, *, pilot: bool = False) -> BlV4Case:
    """Deployment trust: only templates with >0% BL on v2 full test (n≥5)."""
    templates = [
        (
            "html-comment-reflect",
            "java/xss",
            "xss",
            """
            String safe = param.replace("-->", "");
            response.getWriter().println("<!-- " + safe + " -->"); @sink
            """,
            "User content embedded in HTML comment with delimiter strip.",
            "Comment breakout depends on parser; combined with surrounding template unknown.",
            "--> injection breaks comment context.",
            "Fragment never served as HTML to browsers.",
            ["Is this included in HTML pages?", "Template adds further encoding?"],
            "",
        ),
        (
            "audit-event-user-detail",
            "java/error-message-exposure",
            "error-message-exposure",
            """
            java.util.Map<String, String> evt = new java.util.HashMap<>();
            evt.put("detail", param);
            request.setAttribute("auditEvent", evt);
            response.getWriter().println("logged"); @sink
            """,
            "Audit payload attached to request for downstream logging.",
            "Whether audit pipeline stores, forwards, or drops detail needs infra context.",
            "Sensitive data persisted in immutable audit trail.",
            "Audit sink drops detail field in prod configuration.",
            ["Where does auditEvent go?", "Is field encrypted at rest?"],
            "",
        ),
        (
            "sql-built-request-attribute",
            "java/sql-injection",
            "sql-injection",
            """
            String q = "UPDATE accounts SET note='" + param + "' WHERE id=1";
            request.setAttribute("pendingSql", q);
            response.getWriter().println("accepted"); @sink
            """,
            "Dynamic SQL stored on request; execution not in this method.",
            "Cannot see whether pendingSql reaches JDBC without tracing deployment.",
            "Downstream filter executes the string on production DB.",
            "Attribute consumed only by disabled admin servlet.",
            ["What reads pendingSql?", "Is sql.exec.enabled true in prod?"],
            "",
        ),
    ]
    tpl, rule, cwe, body, msg, bl, tp, fp, qs, helpers = templates[variant % len(templates)]
    return _mk(seq, pilot=pilot, variant=variant, category="deployment_trust", cwe=cwe, rule=rule, tpl=tpl,
               body=body, message=msg, bl=bl, tp=tp, fp=fp, qs=qs, class_helpers=helpers)


def _gen_semi_trusted(seq: int, variant: int, *, pilot: bool = False) -> BlV4Case:
    """Semi-trusted: trust-chain patterns; drop always-TP role/header templates."""
    templates = [
        (
            "session-partner-url",
            "java/xss",
            "xss",
            """
            Object v = request.getSession().getAttribute("partnerCallback");
            if (v == null) return;
            String url = v.toString();
            String suffix = getServletContext().getInitParameter("partner.domain.suffix");
            if (url.startsWith("https://") && suffix != null && url.contains(suffix)) {
                response.sendRedirect(url); @sink
            }
            """,
            "Redirect uses session partner URL with https prefix gate only.",
            "Session value may be set by trusted onboarding; https-only gate does not prove partner safety.",
            "Attacker poisons session before redirect.",
            "Only signed server callback writes partnerCallback.",
            ["Who sets partnerCallback?", "Are redirect targets allowlisted downstream?"],
        ),
        (
            "init-param-regex",
            "java/xss",
            "xss",
            """
            String pat = getServletContext().getInitParameter("safe.pattern");
            if (pat != null && param.matches(pat)) {
                response.getWriter().println(param); @sink
            }
            """,
            "Output allowed when input matches deploy-time regex init parameter.",
            "Init params are admin-controlled; regex strength and change control determine if this is trust or misconfig.",
            "Weak regex from admin misconfig allows XSS.",
            "Regex reviewed in change-managed deployment manifest.",
            ["Who can change init params?", "Was regex red-teamed?"],
        ),
        (
            "cookie-prefixed-trust",
            "java/xss",
            "xss",
            """
            javax.servlet.http.Cookie[] cs = request.getCookies();
            if (cs == null) return;
            String val = null;
            for (javax.servlet.http.Cookie c : cs) {
                if ("TRUSTED_PREF".equals(c.getName())) { val = c.getValue(); break; }
            }
            if (val == null) return;
            String out = org.owasp.encoder.Encode.forHtml(val);
            response.getWriter().println(out); @sink
            """,
            "Echo server cookie value after HTML encoding; no param fallback.",
            "Cookie provenance and HttpOnly/Secure flags decide attacker control; encoding may suffice for context.",
            "Forged cookie without HttpOnly reaches sink.",
            "Cookie set server-side HttpOnly on login only.",
            ["Who sets TRUSTED_PREF?", "Is encoding sufficient for response Content-Type?"],
        ),
        (
            "oauth-state-parameter",
            "java/xss",
            "xss",
            """
            String state = request.getParameter("state");
            if (state == null) return;
            String redirect = (String) request.getSession().getAttribute("oauth_state_" + state);
            if (redirect != null && redirect.startsWith("/")) {
                response.sendRedirect(redirect); @sink
            }
            """,
            "OAuth-style state maps to relative redirect in session.",
            "Relative redirect limit helps but session binding to IDP flow is not shown.",
            "Attacker fixes state to poison session mapping.",
            "State single-use and populated only from IDP callback filter.",
            ["How is oauth_state_* populated?", "Is state bound to IDP response?"],
        ),
    ]
    tpl, rule, cwe, body, msg, bl, tp, fp, qs = templates[variant % len(templates)]
    return _mk(seq, pilot=pilot, variant=variant, category="semi_trusted_input", cwe=cwe, rule=rule, tpl=tpl,
               body=body, message=msg, bl=bl, tp=tp, fp=fp, qs=qs)


_GENERATORS: dict[str, Callable[..., BlV4Case]] = {
    "bypassable_mitigation": _gen_bypassable,
    "dns_rebinding": _gen_dns_rebinding,
    "deployment_trust": _gen_deployment_trust,
    "semi_trusted_input": _gen_semi_trusted,
}

SYNTHETIC_QUOTAS: dict[str, int] = {
    "bypassable_mitigation": 80,
    "dns_rebinding": 120,
    "deployment_trust": 100,
    "semi_trusted_input": 100,
}

# All-synthetic 900 — same category mix as published mixed v4 borderline
FULL_SYNTHETIC_QUOTAS: dict[str, int] = {
    "bypassable_mitigation": 460,
    "dns_rebinding": 120,
    "deployment_trust": 100,
    "semi_trusted_input": 220,
}


def generate_pool(*, pilot: bool = False, quotas: dict[str, int] | None = None) -> list[BlV4Case]:
    if quotas is None:
        quotas = {cat: 10 for cat in _GENERATORS} if pilot else SYNTHETIC_QUOTAS
    out: list[BlV4Case] = []
    seq = 1
    for cat, count in quotas.items():
        gen = _GENERATORS[cat]
        for i in range(count):
            out.append(gen(seq, i, pilot=pilot))
            seq += 1
    return out


def generate_pilot_pool(n_per_category: int = 10) -> list[BlV4Case]:
    return generate_pool(pilot=True) if n_per_category == 10 else _generate_pilot_custom(n_per_category)


def _generate_pilot_custom(n_per_category: int) -> list[BlV4Case]:
    out: list[BlV4Case] = []
    seq = 1
    for cat in _GENERATORS:
        gen = _GENERATORS[cat]
        for i in range(n_per_category):
            out.append(gen(seq, i, pilot=True))
            seq += 1
    return out


def to_case_json(sc: BlV4Case) -> dict[str, Any]:
    alert = make_alert(
        rule_id=sc.rule_id,
        rel_uri=sc.rel_file,
        start_line=sc.sink_line,
        message=sc.message,
    )
    base = wrap_codeql([alert])
    base.update(
        {
            "case_id": sc.case_id,
            "gold_track": "BL",
            "acceptable_labels": BL_V4_ACCEPTABLE_LABELS,
            "borderline_version": BL_V4_VERSION,
            "borderline_category": sc.borderline_category,
            "borderline_rationale": sc.borderline_rationale,
            "bl_argument": sc.bl_argument,
            "tp_argument": sc.tp_argument,
            "fp_argument": sc.fp_argument,
            "bl_context_questions": sc.bl_context_questions,
            "dispute_resolution": "TP|FP disagreement → BL",
            "synthetic": True,
            "synthetic_tier": "curated_v4_calibrated_v3",
            "validation_tier": "design_curated_v4_calibrated_v3",
            "cwe_bucket": sc.cwe_bucket,
            "template_id": sc.template_id,
            "codeql_origin": "synthetic_v4",
        }
    )
    return base
