"""Generate synthetic borderline candidates (v2): no label leakage, partial-sanitization only."""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from typing import Any

from lib.codeql_alert import make_alert, wrap_codeql

JAVA_PKG = "org.owasp.benchmark.testcode.synthetic"
REL_PREFIX = f"src/main/java/{JAVA_PKG.replace('.', '/')}"

# Candidate pool quotas (sum = 1200); top 900 selected after model validation.
# Pool size 2400 (2x target) so validation can keep 900 with TP+FP model split.
CWE_QUOTAS_POOL: list[tuple[str, int]] = [
    ("xss", 700),
    ("sql-injection", 400),
    ("command-line-injection", 220),
    ("path-injection", 220),
    ("error-message-exposure", 200),
    ("ldapi", 140),
    ("insecure-cookie", 200),
    ("insecure-randomness", 200),
    ("tainted-format-string", 60),
    ("other-injection", 60),
]

RULE_IDS = {
    "xss": "java/xss",
    "sql-injection": "java/sql-injection",
    "command-line-injection": "java/command-line-injection",
    "path-injection": "java/path-injection",
    "error-message-exposure": "java/error-message-exposure",
    "insecure-cookie": "java/insecure-cookie",
    "insecure-randomness": "java/insecure-randomness",
    "ldapi": "java/ldapi",
    "tainted-format-string": "java/tainted-format-string",
    "other-injection": "java/xss",
}


@dataclass
class SyntheticCase:
    case_id: str
    cwe_bucket: str
    java_source: str
    rel_file: str
    sink_line: int
    rule_id: str
    message: str
    template_id: str
    tp_argument: str
    fp_argument: str
    borderline_rationale: str


def _case_id(n: int, *, prefix: str = "BLCandidate") -> str:
    return f"{prefix}{n:05d}"


def _header(class_name: str, servlet_path: str) -> str:
    return textwrap.dedent(
        f"""
        /**
         * OWASP Benchmark Project v1.2
         *
         * @author Nick Sanidas
         * @created 2015
         */
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
            protected void doGet(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {{
                doPost(request, response);
            }}

            @Override
            protected void doPost(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {{
                response.setContentType("text/html;charset=UTF-8");
                String param = request.getParameter("{class_name}");
                if (param == null) {{
                    param = "";
                }}
        """
    ).strip()


def _footer() -> str:
    return "\n    }\n}\n"


def _assemble(class_name: str, servlet_path: str, body: str) -> tuple[str, int]:
    """Return (full_java, sink_line) where sink is marked by line containing @sink."""
    header = _header(class_name, servlet_path)
    body = textwrap.dedent(body).strip("\n")
    lines = body.split("\n")
    sink_line: int | None = None
    out_lines: list[str] = []
    for line in lines:
        if "@sink" in line:
            sink_line = header.count("\n") + 1 + len(out_lines) + 1
            line = line.replace("@sink", "").rstrip()
            if line.strip():
                out_lines.append(line)
        else:
            out_lines.append(line)
    if sink_line is None:
        raise ValueError("body must contain a @sink marker line")
    java = header + "\n" + "\n".join(out_lines) + _footer()
    return java, sink_line


def _gen_xss(idx: int, class_name: str, variant: int) -> SyntheticCase:
    servlet_path = f"xss/{class_name}"
    if variant % 7 == 0:
        body = """
            String bar = org.springframework.web.util.HtmlUtils.htmlEscape(param);
            String baz = param;
            response.getWriter().println("<script>var msg='" + baz + "';</script>"); @sink
        """
        tpl = "xss-sanitized-wrong-variable"
        tp = "Sink uses unsanitized variable; escape on bar does not protect the output path."
        fp = "Code shows HtmlUtils.htmlEscape in scope; reviewer may assume param is covered."
        rationale = "Sanitization applied to a different variable than the sink uses."
        msg = "Cross-site scripting vulnerability due to user-provided value."
        java, sink_line = _assemble(class_name, servlet_path, body)
        return SyntheticCase(
            case_id=_case_id(idx),
            cwe_bucket="xss",
            java_source=java,
            rel_file=f"{REL_PREFIX}/{class_name}.java",
            sink_line=sink_line,
            rule_id=RULE_IDS["xss"],
            message=msg,
            template_id=tpl,
            tp_argument=tp,
            fp_argument=fp,
            borderline_rationale=rationale,
        )
    if variant % 7 == 1:
        body = """
            String bar = param;
            if (false) {
                bar = org.springframework.web.util.HtmlUtils.htmlEscape(bar);
            }
            response.getWriter().println(bar); @sink
        """
        tpl = "xss-sanitization-dead-branch"
        tp = "Live path reflects raw param; sanitization only appears in unreachable branch."
        fp = "Sanitization call is visible in the same method; static analysis may assume coverage."
        rationale = "Mitigation exists only on a provably dead branch."
        java, sink_line = _assemble(class_name, servlet_path, body)
        return SyntheticCase(
            case_id=_case_id(idx),
            cwe_bucket="xss",
            java_source=java,
            rel_file=f"{REL_PREFIX}/{class_name}.java",
            sink_line=sink_line,
            rule_id=RULE_IDS["xss"],
            message="Cross-site scripting vulnerability due to user-provided value.",
            template_id=tpl,
            tp_argument=tp,
            fp_argument=fp,
            borderline_rationale=rationale,
        )
    if variant % 3 == 0:
        body = """
            String bar = org.springframework.web.util.HtmlUtils.htmlEscape(param);
            response.getWriter().println("<script>var msg = '" + bar + "';</script>"); @sink
        """
        tpl = "xss-html-escape-in-js-context"
        tp = "HtmlUtils does not make data safe inside a JS string; breakout payloads remain plausible."
        fp = "Standard HTML metacharacters are escaped; simple HTML injection paths are blocked."
        rationale = "Context mismatch: HTML encoder applied, JavaScript string sink."
        msg = "Cross-site scripting vulnerability due to user-provided value."
    elif variant % 3 == 1:
        body = """
            String bar = param.replaceAll("(?i)<script>", "");
            response.getWriter().println(bar); @sink
        """
        tpl = "xss-blacklist-script-tag"
        tp = "Blacklist sanitizer is bypassable with alternate tags or events."
        fp = "Obvious script-tag vectors are stripped before reflection."
        rationale = "Weak blacklist sanitizer on reflected output."
        msg = "Cross-site scripting vulnerability due to user-provided value."
    else:
        body = """
            String bar = param.replace("\\"", "&quot;");
            response.getWriter().println("<div id='user' data-name='" + bar + "'></div>"); @sink
        """
        tpl = "xss-partial-attribute-escape"
        tp = "Only quotes escaped; event-handler or tag-breakout may remain."
        fp = "Double-quote breakout is mitigated for attribute embedding."
        rationale = "Partial attribute escaping on reflected attribute value."
        msg = "Cross-site scripting vulnerability due to user-provided value."
    java, sink_line = _assemble(class_name, servlet_path, body)
    return SyntheticCase(
        case_id=_case_id(idx),
        cwe_bucket="xss",
        java_source=java,
        rel_file=f"{REL_PREFIX}/{class_name}.java",
        sink_line=sink_line,
        rule_id=RULE_IDS["xss"],
        message=msg,
        template_id=tpl,
        tp_argument=tp,
        fp_argument=fp,
        borderline_rationale=rationale,
    )


def _gen_sqli(idx: int, class_name: str, variant: int) -> SyntheticCase:
    servlet_path = f"sqli/{class_name}"
    if variant % 5 == 0:
        body = """
            String bar = param.replace("'", "''");
            String baz = param;
            java.sql.Connection conn = null;
            try {
                javax.naming.InitialContext ctx = new javax.naming.InitialContext();
                conn = ((javax.sql.DataSource) ctx.lookup("java:comp/env/jdbc/BenchmarkDB")).getConnection();
                String sql = "SELECT * FROM USERS WHERE name = '" + baz + "'";
                conn.createStatement().executeQuery(sql); @sink
            } finally {
                if (conn != null) try { conn.close(); } catch (Exception e) {}
            }
        """
        java, sink_line = _assemble(class_name, servlet_path, body)
        return SyntheticCase(
            case_id=_case_id(idx),
            cwe_bucket="sql-injection",
            java_source=java,
            rel_file=f"{REL_PREFIX}/{class_name}.java",
            sink_line=sink_line,
            rule_id=RULE_IDS["sql-injection"],
            message="Query built from user-controlled source.",
            template_id="sqli-sanitized-wrong-variable",
            tp_argument="Sink concatenates unsanitized baz; quote-escape on bar is irrelevant.",
            fp_argument="Quote-escape on bar suggests SQL escaping was attempted in the method.",
            borderline_rationale="Sanitization on a variable not used in the SQL sink.",
        )
    if variant % 2 == 0:
        body = """
            String bar = param.replace("'", "''");
            java.sql.Connection conn = null;
            try {
                javax.naming.InitialContext ctx = new javax.naming.InitialContext();
                conn = ((javax.sql.DataSource) ctx.lookup("java:comp/env/jdbc/BenchmarkDB")).getConnection();
                String sql = "SELECT * FROM USERS WHERE name = '" + bar + "'";
                conn.createStatement().executeQuery(sql); @sink
            } finally {
                if (conn != null) try { conn.close(); } catch (Exception e) {}
            }
        """
        tpl = "sqli-quote-escape-not-prepared"
    else:
        body = """
            String bar = param;
            java.sql.Connection conn = null;
            try {
                javax.naming.InitialContext ctx = new javax.naming.InitialContext();
                conn = ((javax.sql.DataSource) ctx.lookup("java:comp/env/jdbc/BenchmarkDB")).getConnection();
                java.sql.PreparedStatement ps = conn.prepareStatement("SELECT * FROM USERS WHERE id = ?");
                ps.setString(1, bar);
                ps.executeQuery();
                String logSql = "LOG " + bar;
                conn.createStatement().execute(logSql); @sink
            } finally {
                if (conn != null) try { conn.close(); } catch (Exception e) {}
            }
        """
        tpl = "sqli-prepared-plus-log-concat"
    java, sink_line = _assemble(class_name, servlet_path, body)
    return SyntheticCase(
        case_id=_case_id(idx),
        cwe_bucket="sql-injection",
        java_source=java,
        rel_file=f"{REL_PREFIX}/{class_name}.java",
        sink_line=sink_line,
        rule_id=RULE_IDS["sql-injection"],
        message="Query built from user-controlled source.",
        template_id=tpl,
        tp_argument="User input influences SQL text without guaranteed parameterization on all paths.",
        fp_argument="Primary query uses prepared statements; secondary path may be dead in deployment.",
        borderline_rationale="Mixed parameterization and string-built SQL on related paths.",
    )


def _gen_cmdi(idx: int, class_name: str, variant: int) -> SyntheticCase:
    servlet_path = f"cmdi/{class_name}"
    body = """
        String bar = param.replaceAll("[;&|`$]", "");
        String[] args = { "sh", "-c", "echo " + bar };
        Runtime.getRuntime().exec(args); @sink
    """
    java, sink_line = _assemble(class_name, servlet_path, body)
    return SyntheticCase(
        case_id=_case_id(idx),
        cwe_bucket="command-line-injection",
        java_source=java,
        rel_file=f"{REL_PREFIX}/{class_name}.java",
        sink_line=sink_line,
        rule_id=RULE_IDS["command-line-injection"],
        message="Command depends on user-provided value.",
        template_id="cmdi-partial-metachar-strip",
        tp_argument="Sanitizer does not cover all shell metacharacters or expansion forms.",
        fp_argument="Common metacharacters are stripped before a fixed echo command.",
        borderline_rationale="Partial shell metacharacter filtering before exec.",
    )


def _gen_path(idx: int, class_name: str, variant: int) -> SyntheticCase:
    servlet_path = f"path/{class_name}"
    body = """
        String bar = param.replace("../", "");
        java.io.File f = new java.io.File("/var/benchmark/uploads", bar);
        response.getWriter().println("Path: " + f.getPath()); @sink
    """
    java, sink_line = _assemble(class_name, servlet_path, body)
    return SyntheticCase(
        case_id=_case_id(idx),
        cwe_bucket="path-injection",
        java_source=java,
        rel_file=f"{REL_PREFIX}/{class_name}.java",
        sink_line=sink_line,
        rule_id=RULE_IDS["path-injection"],
        message="User input may influence file path.",
        template_id="path-partial-traversal-strip",
        tp_argument="Traversal may bypass naive stripping without canonicalization.",
        fp_argument="Literal ../ removed; path confined under fixed base directory.",
        borderline_rationale="Incomplete path normalization on user input.",
    )


def _gen_error_leak(idx: int, class_name: str, variant: int) -> SyntheticCase:
    servlet_path = f"err/{class_name}"
    body = """
        try {
            int x = Integer.parseInt(param);
            response.getWriter().println("ok " + x);
        } catch (Exception e) {
            String safe = org.springframework.web.util.HtmlUtils.htmlEscape(e.getMessage());
            if ("true".equals(request.getParameter("debug"))) {
                response.getWriter().println(java.util.Arrays.toString(e.getStackTrace())); @sink
            } else {
                response.getWriter().println("error: " + safe);
            }
        }
    """
    java, sink_line = _assemble(class_name, servlet_path, body)
    return SyntheticCase(
        case_id=_case_id(idx),
        cwe_bucket="error-message-exposure",
        java_source=java,
        rel_file=f"{REL_PREFIX}/{class_name}.java",
        sink_line=sink_line,
        rule_id=RULE_IDS["error-message-exposure"],
        message="Error message or stack trace may be exposed to the user.",
        template_id="error-debug-branch-stack",
        tp_argument="Debug flag enables stack trace disclosure.",
        fp_argument="Default path returns sanitized message only.",
        borderline_rationale="Conditional verbose error handling.",
    )


def _gen_cookie(idx: int, class_name: str, variant: int) -> SyntheticCase:
    servlet_path = f"cookie/{class_name}"
    if variant % 2 == 0:
        body = """
            String value = param;
            if (value.length() > 128) {
                value = value.substring(0, 128);
            }
            javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SESSION", value);
            cookie.setHttpOnly(true);
            cookie.setSecure(false);
            cookie.setPath("/internal/");
            response.addCookie(cookie); @sink
        """
        tpl = "cookie-secure-false-scoped-path"
        tp = "Secure=false on session cookie may be sent over HTTPS in production."
        fp = "HttpOnly set, path scoped to /internal/, length capped; may be HTTP-only zone."
    else:
        body = """
            String value = org.springframework.web.util.HtmlUtils.htmlEscape(param);
            javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("PREF", value);
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setMaxAge(3600);
            if ("http".equalsIgnoreCase(request.getScheme())) {
                cookie.setSecure(false);
            }
            response.addCookie(cookie); @sink
        """
        tpl = "cookie-secure-scheme-conditional"
        tp = "Secure disabled on HTTP allows session cookie downgrade when HTTPS is expected."
        fp = "Secure flag follows request scheme; reasonable for mixed deployments."
    java, sink_line = _assemble(class_name, servlet_path, body)
    return SyntheticCase(
        case_id=_case_id(idx),
        cwe_bucket="insecure-cookie",
        java_source=java,
        rel_file=f"{REL_PREFIX}/{class_name}.java",
        sink_line=sink_line,
        rule_id=RULE_IDS["insecure-cookie"],
        message="Cookie is added without the secure flag being set.",
        template_id=tpl,
        tp_argument=tp,
        fp_argument=fp,
        borderline_rationale="Cookie flags depend on deployment assumptions.",
    )


def _gen_random(idx: int, class_name: str, variant: int) -> SyntheticCase:
    servlet_path = f"rand/{class_name}"
    if variant % 2 == 0:
        body = """
            long seed = param.hashCode() ^ System.currentTimeMillis();
            java.util.Random r = new java.util.Random(seed);
            String token = Long.toHexString(r.nextLong());
            response.getWriter().println("token=" + token); @sink
        """
        tpl = "random-user-mixed-seed"
        tp = "Token derived from predictable PRNG with user-influenced seed."
        fp = "Seed mixes system time; token appears non-security-critical in snippet."
    else:
        body = """
            byte[] bytes = new byte[16];
            java.security.SecureRandom sr = new java.security.SecureRandom();
            sr.setSeed(param.getBytes("UTF-8"));
            sr.nextBytes(bytes);
            String token = javax.xml.bind.DatatypeConverter.printHexBinary(bytes);
            response.getWriter().println("token=" + token); @sink
        """
        tpl = "random-secure-random-user-seed"
        tp = "setSeed with user bytes weakens CSPRNG entropy."
        fp = "SecureRandom used; additional seed may not dominate output."
    java, sink_line = _assemble(class_name, servlet_path, body)
    return SyntheticCase(
        case_id=_case_id(idx),
        cwe_bucket="insecure-randomness",
        java_source=java,
        rel_file=f"{REL_PREFIX}/{class_name}.java",
        sink_line=sink_line,
        rule_id=RULE_IDS["insecure-randomness"],
        message="Random data depends on user-controlled value.",
        template_id=tpl,
        tp_argument=tp,
        fp_argument=fp,
        borderline_rationale="User input influences PRNG seeding.",
    )


def _gen_ldap(idx: int, class_name: str, variant: int) -> SyntheticCase:
    servlet_path = f"ldap/{class_name}"
    body = r"""
        String bar = param.replace("*", "\\2a").replace("(", "\\28").replace(")", "\\29");
        String filter = "(uid=" + bar + ")";
        javax.naming.directory.DirContext ctx = null;
        try {
            java.util.Hashtable<String, String> env = new java.util.Hashtable<>();
            env.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(javax.naming.Context.PROVIDER_URL, "ldap://localhost:389");
            ctx = new javax.naming.directory.InitialDirContext(env);
            ctx.search("ou=users", filter, new javax.naming.directory.SearchControls()); @sink
        } catch (Exception e) {
            response.getWriter().println("ldap error");
        } finally {
            if (ctx != null) try { ctx.close(); } catch (Exception e) {}
        }
    """
    java, sink_line = _assemble(class_name, servlet_path, body)
    return SyntheticCase(
        case_id=_case_id(idx),
        cwe_bucket="ldapi",
        java_source=java,
        rel_file=f"{REL_PREFIX}/{class_name}.java",
        sink_line=sink_line,
        rule_id=RULE_IDS["ldapi"],
        message="LDAP query built with user input.",
        template_id="ldap-partial-metachar-escape",
        tp_argument="LDAP filter escaping is incomplete for all metacharacters.",
        fp_argument="Common LDAP metacharacters are escaped before filter use.",
        borderline_rationale="Partial LDAP filter escaping on concatenated filter.",
    )


def _gen_format(idx: int, class_name: str, variant: int) -> SyntheticCase:
    servlet_path = f"fmt/{class_name}"
    body = """
        String bar = param.replace("%", "%%");
        response.getWriter().println(String.format("User value: %s", bar)); @sink
    """
    java, sink_line = _assemble(class_name, servlet_path, body)
    return SyntheticCase(
        case_id=_case_id(idx),
        cwe_bucket="tainted-format-string",
        java_source=java,
        rel_file=f"{REL_PREFIX}/{class_name}.java",
        sink_line=sink_line,
        rule_id=RULE_IDS["tainted-format-string"],
        message="Format string may include user-controlled data.",
        template_id="format-literal-template",
        tp_argument="Tainted data in format call may be abusable with unexpected specifiers.",
        fp_argument="Format template is literal; user data is only an argument.",
        borderline_rationale="String.format with tainted argument vs format injection.",
    )


def _gen_other(idx: int, class_name: str, variant: int) -> SyntheticCase:
    servlet_path = f"href/{class_name}"
    body = """
        String bar = param.replace("javascript:", "");
        response.getWriter().println("<a href='" + bar + "'>link</a>"); @sink
    """
    java, sink_line = _assemble(class_name, servlet_path, body)
    return SyntheticCase(
        case_id=_case_id(idx),
        cwe_bucket="other-injection",
        java_source=java,
        rel_file=f"{REL_PREFIX}/{class_name}.java",
        sink_line=sink_line,
        rule_id=RULE_IDS["other-injection"],
        message="User input reflected in HTML.",
        template_id="href-protocol-strip",
        tp_argument="Alternate URI schemes or encoding may bypass protocol strip.",
        fp_argument="javascript: prefix removed from href value.",
        borderline_rationale="Protocol blacklist on href attribute.",
    )


_GENERATORS = {
    "xss": _gen_xss,
    "sql-injection": _gen_sqli,
    "command-line-injection": _gen_cmdi,
    "path-injection": _gen_path,
    "error-message-exposure": _gen_error_leak,
    "insecure-cookie": _gen_cookie,
    "insecure-randomness": _gen_random,
    "ldapi": _gen_ldap,
    "tainted-format-string": _gen_format,
    "other-injection": _gen_other,
}


def build_cwe_schedule_pool() -> list[str]:
    schedule: list[str] = []
    for bucket, count in CWE_QUOTAS_POOL:
        schedule.extend([bucket] * count)
    assert len(schedule) == 2400, len(schedule)
    return schedule


def generate_case(global_idx: int, cwe_bucket: str) -> SyntheticCase:
    class_name = _case_id(global_idx)
    return _GENERATORS[cwe_bucket](global_idx, class_name, global_idx)


def to_case_json(sc: SyntheticCase) -> dict[str, Any]:
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
            "acceptable_labels": ["TP", "FP"],
            "synthetic": True,
            "synthetic_tier": "full_v2_validated",
            "cwe_bucket": sc.cwe_bucket,
            "template_id": sc.template_id,
            "borderline_rationale": sc.borderline_rationale,
            "tp_argument": sc.tp_argument,
            "fp_argument": sc.fp_argument,
            "codeql_origin": "synthetic_template_aligned",
            "benchmark_real_vuln": None,
        }
    )
    return base


def generate_pool(n: int | None = None) -> list[tuple[SyntheticCase, dict[str, Any]]]:
    schedule = build_cwe_schedule_pool()
    if n is not None:
        schedule = schedule[:n]
    out: list[tuple[SyntheticCase, dict[str, Any]]] = []
    for i, bucket in enumerate(schedule, start=1):
        sc = generate_case(i, bucket)
        out.append((sc, to_case_json(sc)))
    return out
