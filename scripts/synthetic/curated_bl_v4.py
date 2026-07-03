"""Borderline v4 synthetic cases — principled BL categories (pilot + full pool)."""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from typing import Any, Callable

from lib.bl_categories import BL_V4_ACCEPTABLE_LABELS, BL_V4_VERSION, CATEGORY_LABELS
from lib.codeql_alert import make_alert, wrap_codeql

JAVA_PKG = "org.owasp.benchmark.testcode.blv4"
REL_PREFIX = f"src/main/java/{JAVA_PKG.replace('.', '/')}"

FORBIDDEN = ("Synthetic", "SINK:", "borderline", "BL v4 hint")


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


def case_id(n: int, *, pilot: bool = False) -> str:
    return f"BLv4p{n:05d}" if pilot else f"BLv4{n:05d}"


def class_name(n: int) -> str:
    return f"BlV4_{n:05d}"


def _header(class_name: str, servlet_path: str) -> str:
    return textwrap.dedent(
        f"""
        package {JAVA_PKG};

        import java.io.IOException;
        import javax.servlet.ServletException;
        import javax.servlet.annotation.WebServlet;
        import javax.servlet.http.HttpServlet;
        import javax.servlet.http.HttpServletRequest;
        import javax.servlet.http.HttpServletResponse;

        @WebServlet(value = "/benchmark/{servlet_path}")
        public class {class_name} extends HttpServlet {{
            private static final long serialVersionUID = 1L;

            @Override
            protected void doPost(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {{
                response.setContentType("text/html;charset=UTF-8");
                String param = request.getParameter("data");
                if (param == null) param = "";
        """
    ).strip()


def _footer() -> str:
    return "\n    }\n}\n"


def _assemble(class_name: str, servlet_path: str, body: str) -> tuple[str, int]:
    header = _header(class_name, servlet_path)
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


def _mk(
    seq: int,
    clazz: str,
    *,
    pilot: bool,
    category: str,
    cwe: str,
    rule: str,
    tpl: str,
    servlet_path: str,
    body: str,
    message: str,
    bl: str,
    tp: str,
    fp: str,
    qs: list[str],
) -> BlV4Case:
    java, sink = _assemble(clazz, servlet_path, body)
    return BlV4Case(
        case_id=case_id(seq, pilot=pilot),
        borderline_category=category,
        cwe_bucket=cwe,
        java_source=java,
        rel_file=f"{REL_PREFIX}/{clazz}.java",
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


# --- 10 bypassable templates: mitigation present; bypass/deployment not decidable from snippet alone ---

def _gen_bypassable(seq: int, clazz: str, variant: int, *, pilot: bool = False) -> BlV4Case:
    v = variant % 10
    path = f"blv4/bypass/{clazz}"
    templates = [
        (
            "xss-html-encode-in-script-context",
            "java/xss",
            "xss",
            """
            String bar = org.owasp.encoder.encoder.encodeForHTML(param);
            response.getWriter().println("<script>var x='" + bar + "';</script>"); @sink
            """,
            "Cross-site scripting in JavaScript string context.",
            "HTML encoding may be wrong context for a JS string sink; exploitability depends on quoting and browser behavior.",
            "Breakout from JS string with encoded payload may still be possible.",
            "HTML encoder blocks angle brackets; may be sufficient for this static template.",
            ["Is this response ever served as text/html with active script?", "Is CSP enforced?"],
        ),
        (
            "allowlist-regex-host-userinfo",
            "java/path-injection",
            "path-injection",
            """
            String host = param;
            if (host.matches("^[a-zA-Z0-9.-]+\\\\.safe\\\\.com$")) {
                response.sendRedirect("https://" + host + "/home"); @sink
            }
            """,
            "Redirect with hostname allowlist pattern.",
            "Regex may miss userinfo@host, homoglyphs, or parser differentials — needs security review, not instant TP.",
            "Clever hostname tricks may bypass the regex.",
            "Pattern may match internal security standard; redirects validated elsewhere.",
            ["Are redirects followed server-side?", "Is there an outbound URL proxy policy?"],
        ),
        (
            "private-ip-block-incomplete",
            "java/path-injection",
            "path-injection",
            """
            String url = param;
            if (!url.contains("127.0.0.1") && url.startsWith("http://")) {
                java.io.InputStream in = new java.net.URL(url).openStream(); @sink
            }
            """,
            "Outbound fetch with partial internal IP block.",
            "Blocks literal 127.0.0.1 only; localhost, ::1, decimal/hex IP forms may still apply — context needed.",
            "Alternate IP representations reach internal targets.",
            "Corporate proxy may block all RFC1918 regardless of this check.",
            ["Is egress filtered at the network layer?", "Which IP forms does the HTTP stack normalize?"],
        ),
        (
            "xss-blacklist-events",
            "java/xss",
            "xss",
            """
            String bar = param.replaceAll("(?i)<script|onerror|onclick", "");
            response.getWriter().println("<div>" + bar + "</div>"); @sink
            """,
            "Reflected output with partial tag/event blacklist.",
            "Blacklist stops naive payloads; less common vectors may remain — skilled bypass vs policy call.",
            "Alternate tags/events bypass the blacklist.",
            "Output may be low-risk internal admin UI only.",
            ["Who can reach this endpoint?", "Is DOMPurify applied client-side?"],
        ),
        (
            "url-decode-once-before-check",
            "java/path-injection",
            "path-injection",
            """
            String once = java.net.URLDecoder.decode(param, "UTF-8");
            if (!once.contains("..")) {
                java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/data/" + once)); @sink
                response.getWriter().println("ok"); @sink
            }
            """,
            "Path read after single URL decode and substring check.",
            "Double-encoding or normalization may evade .. check; /data sensitivity unknown from code.",
            "Encoded traversal may read arbitrary files under /data.",
            "/data may hold only public assets; WAF may normalize encoding.",
            ["What is stored under /data/?", "Is double-decoding possible before the check?"],
        ),
        (
            "scheme-prefix-only",
            "java/path-injection",
            "path-injection",
            """
            String target = param;
            if (target.startsWith("https://")) {
                java.net.HttpURLConnection conn =
                    (java.net.HttpURLConnection) new java.net.URL(target).openConnection(); @sink
                conn.getResponseCode();
            }
            """,
            "HTTPS prefix check before server-side fetch.",
            "Scheme check does not prove safe host; internal metadata endpoints may still be reachable.",
            "Attacker supplies https://evil or parser-confused URL.",
            "Egress allowlist or service mesh may restrict destinations.",
            ["Is there a second-stage host allowlist?", "Can this reach cloud metadata URLs?"],
        ),
        (
            "sql-escape-apostrophe-only",
            "java/sql-injection",
            "sql-injection",
            """
            String bar = param.replace("'", "''");
            String sql = "SELECT * FROM users WHERE name='" + bar + "'";
            java.sql.Connection con = (java.sql.Connection) request.getAttribute("dbConn");
            if (con != null) {
                java.sql.Statement st = con.createStatement();
                st.executeQuery(sql); @sink
            }
            """,
            "SQL with apostrophe doubling only.",
            "Escaping quotes does not address all SQLi vectors (numeric, stacked queries, dialect quirks).",
            "Classic quote escape bypassed by encoding or alternate syntax.",
            "Driver may use prepared statements layer; DB may be read-only replica.",
            ["Which DB dialect and privileges apply?", "Is this attribute ever null in production?"],
        ),
        (
            "ldap-filter-escape-partial",
            "java/ldapi",
            "ldapi",
            """
            String filter = "(uid=" + param.replace("*", "\\\\2a").replace("(", "\\\\28") + ")";
            javax.naming.directory.InitialDirContext ctx =
                new javax.naming.directory.InitialDirContext();
            ctx.search("ou=users", filter, null); @sink
            """,
            "LDAP filter with partial metachar escape.",
            "Partial escaping may be insufficient for the LDAP dialect; impact depends on directory ACLs.",
            "Remaining metacharacters enable injection.",
            "Directory may be read-only with no sensitive attributes.",
            ["What LDAP server and ACLs are configured?", "Is this code path enabled?"],
        ),
        (
            "path-normalize-after-concat",
            "java/path-injection",
            "path-injection",
            """
            java.io.File base = new java.io.File("/var/uploads");
            java.io.File f = new java.io.File(base, param);
            String norm = f.getCanonicalPath();
            if (norm.startsWith(base.getCanonicalPath())) {
                response.getWriter().println(norm); @sink
            }
            """,
            "Canonical path guard on user filename.",
            "TOCTOU or symlink layout under /var/uploads may change verdict; needs filesystem context.",
            "Symlink escape after check yields traversal.",
            "Upload dir may be chrooted without symlinks.",
            ["Are symlinks allowed in /var/uploads?", "Is this servlet exposed publicly?"],
        ),
        (
            "xss-strip-tags-keep-attributes",
            "java/xss",
            "xss",
            """
            String bar = param.replaceAll("<[^>]+>", "");
            response.getWriter().println(bar); @sink
            """,
            "Tag-stripping sanitizer on HTML output.",
            "Stripping tags can leave dangerous attributes or mutate payload — policy judgment, not clear TP.",
            "Mutation-based XSS may survive tag removal.",
            "Output may be plain text API, not HTML.",
            ["Is Content-Type always text/html?", "Is output consumed only by trusted clients?"],
        ),
    ]
    tpl, rule, cwe, body, msg, bl, tp, fp, qs = templates[v]
    return _mk(seq, clazz, pilot=pilot, category="bypassable_mitigation", cwe=cwe, rule=rule, tpl=tpl,
               servlet_path=path, body=body, message=msg, bl=bl, tp=tp, fp=fp, qs=qs)


def _gen_dns_rebinding(seq: int, clazz: str, variant: int, *, pilot: bool = False) -> BlV4Case:
    v = variant % 10
    path = f"blv4/dns/{clazz}"
    bodies = [
        """
        String target = param;
        java.net.InetAddress addr = java.net.InetAddress.getByName(target);
        if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()) return;
        java.net.URL url = new java.net.URL("http://" + target + "/api");
        url.openStream(); @sink
        """,
        """
        String host = param;
        String ip = java.net.InetAddress.getByName(host).getHostAddress();
        if (ip.startsWith("10.")) return;
        Thread.sleep(50);
        new java.net.URL("http://" + host).openConnection().connect(); @sink
        """,
        """
        String u = param;
        if (!u.contains("127.0.0.1") && !u.contains("localhost")) {
            java.net.InetAddress a = java.net.InetAddress.getByName(new java.net.URL(u).getHost());
            if (!a.isAnyLocalAddress()) {
                new java.net.URL(u).openStream(); @sink
            }
        }
        """,
    ]
    body = bodies[v % len(bodies)]
    return _mk(
        seq, clazz, pilot=pilot, category="dns_rebinding", cwe="ssrf", rule="java/ssrf",
        tpl=f"dns-rebind-variant-{v}", servlet_path=path, body=body,
        message="Separate DNS resolution and outbound fetch.",
        bl="Resolve-then-fetch gap: attacker DNS rebinding may apply depending on TTL, timing, and resolver cache — not provable from snippet.",
        tp="Controlled DNS plus timing could reach internal services.",
        fp="Network egress controls or same-connection fetch may eliminate the window.",
        qs=["What is the DNS TTL for allowed hosts?", "Are resolve and fetch on the same connection?", "Is egress filtered?"],
    )


def _gen_deployment_trust(seq: int, clazz: str, variant: int, *, pilot: bool = False) -> BlV4Case:
    v = variant % 10
    path = f"blv4/deploy/{clazz}"
    templates = [
        (
            "log-sink-sensitive",
            "java/error-message-exposure",
            "error-message-exposure",
            """
            org.slf4j.LoggerFactory.getLogger(getClass()).warn("payload=" + param); @sink
            """,
            "User input written to application logs.",
            "Log exposure, retention, and SIEM parsing determine impact — not visible in code.",
            "Secrets in logs may leak via log aggregation.",
            "Logs restricted to on-call with short retention.",
            ["Who can read logs?", "Do logs feed external analytics?"],
        ),
        (
            "sql-built-not-shown-execute",
            "java/sql-injection",
            "sql-injection",
            """
            String q = "UPDATE accounts SET note='" + param + "' WHERE id=1";
            response.getWriter().println("query built"); @sink
            """,
            "Dynamic SQL string built; execution not shown in method.",
            "Cannot tell if string is executed, logged only, or dead code without deployment trace.",
            "If executed on prod DB, injection applies.",
            "Debug-only branch never deployed.",
            ["Is this string passed to JDBC elsewhere?", "Is endpoint reachable in prod?"],
        ),
        (
            "error-page-reflect",
            "java/error-message-exposure",
            "error-message-exposure",
            """
            response.setStatus(500);
            response.getWriter().println("Error: " + param); @sink
            """,
            "Error response reflects input.",
            "May aid phishing or leak data depending on who receives 500 pages and caching.",
            "Reflected errors enable XSS or info leak.",
            "Errors only shown to authenticated admins.",
            ["Who sees 500 responses?", "Is output encoded?"],
        ),
        (
            "internal-path-no-auth-in-file",
            "java/xss",
            "xss",
            """
            response.getWriter().println(param); @sink
            """,
            "Reflected output on /internal/ route.",
            "Servlet mapped to internal path but authn/z not shown — reachability is deployment question.",
            "If public, XSS applies.",
            "Protected by API gateway requiring mTLS.",
            ["Is /internal behind auth?", "Is there a WAF?"],
        ),
    ]
    tpl, rule, cwe, body, msg, bl, tp, fp, qs = templates[v % len(templates)]
    return _mk(seq, clazz, pilot=pilot, category="deployment_trust", cwe=cwe, rule=rule, tpl=tpl,
               servlet_path=path, body=body, message=msg, bl=bl, tp=tp, fp=fp, qs=qs)


def _gen_semi_trusted(seq: int, clazz: str, variant: int, *, pilot: bool = False) -> BlV4Case:
    v = variant % 10
    path = f"blv4/semi/{clazz}"
    templates = [
        (
            "session-partner-url",
            "java/xss",
            "xss",
            """
            Object v = request.getSession().getAttribute("partnerCallback");
            String url = v != null ? v.toString() : param;
            response.sendRedirect(url); @sink
            """,
            "Redirect uses session-stored partner URL.",
            "Session attribute may be set by trusted onboarding — compromise or scope unclear from this method.",
            "If attacker sets session value, open redirect.",
            "Only admin workflow sets partnerCallback.",
            ["Who writes partnerCallback to the session?", "Is partner API trusted?"],
        ),
        (
            "init-param-regex",
            "java/xss",
            "xss",
            """
            String pat = getServletContext().getInitParameter("safe.pattern");
            if (param.matches(pat)) {
                response.getWriter().println(param); @sink
            }
            """,
            "Output gated by deploy-time regex init parameter.",
            "Init parameters are admin-controlled; misconfiguration risk vs intentional trust boundary.",
            "Weak regex from admin misconfig allows XSS.",
            "Change-controlled regex reviewed by security.",
            ["Who can change init params?", "Was regex tested against abuse cases?"],
        ),
        (
            "cookie-prefixed-trust",
            "java/xss",
            "xss",
            """
            javax.servlet.http.Cookie[] cs = request.getCookies();
            String val = param;
            if (cs != null) {
                for (javax.servlet.http.Cookie c : cs) {
                    if ("TRUSTED_PREF".equals(c.getName())) { val = c.getValue(); break; }
                }
            }
            response.getWriter().println(val); @sink
            """,
            "Output prefers TRUSTED_PREF cookie over parameter.",
            "Cookie may be set by server earlier in flow — attacker control depends on flags and prior handlers.",
            "Attacker forges cookie without HttpOnly.",
            "Cookie server-set HttpOnly on login only.",
            ["Who sets TRUSTED_PREF?", "Is cookie scoped and HttpOnly?"],
        ),
        (
            "oauth-state-parameter",
            "java/xss",
            "xss",
            """
            String state = request.getParameter("state");
            String redirect = (String) request.getSession().getAttribute("oauth_state_" + state);
            if (redirect != null) {
                response.sendRedirect(redirect); @sink
            }
            """,
            "OAuth-style state maps to redirect in session.",
            "Trust model assumes state from identity provider flow — compromise is organizational risk.",
            "Attacker fixes state to poison session mapping.",
            "State single-use and IDP-validated.",
            ["How is oauth_state_* populated?", "Is state bound to IDP response?"],
        ),
    ]
    tpl, rule, cwe, body, msg, bl, tp, fp, qs = templates[v % len(templates)]
    return _mk(seq, clazz, pilot=pilot, category="semi_trusted_input", cwe=cwe, rule=rule, tpl=tpl,
               servlet_path=path, body=body, message=msg, bl=bl, tp=tp, fp=fp, qs=qs)


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


def generate_pool(*, pilot: bool = False) -> list[BlV4Case]:
    quotas = {cat: 10 for cat in _GENERATORS} if pilot else SYNTHETIC_QUOTAS
    out: list[BlV4Case] = []
    seq = 1
    for cat, count in quotas.items():
        gen = _GENERATORS[cat]
        for i in range(count):
            clazz = class_name(seq)
            out.append(gen(seq, clazz, i, pilot=pilot))
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
            clazz = class_name(seq)
            out.append(gen(seq, clazz, i, pilot=True))
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
            "synthetic_tier": "curated_v4_principled",
            "validation_tier": "design_curated_v4",
            "cwe_bucket": sc.cwe_bucket,
            "template_id": sc.template_id,
            "codeql_origin": "synthetic_v4",
        }
    )
    return base
