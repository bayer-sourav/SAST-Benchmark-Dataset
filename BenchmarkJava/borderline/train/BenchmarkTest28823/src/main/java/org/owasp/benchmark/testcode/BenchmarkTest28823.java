package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/xss-02/BenchmarkTest28823")
public class BenchmarkTest28823 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("BenchmarkTest");
        if (param == null) param = "";
javax.servlet.http.Cookie[] cs = request.getCookies();
if (cs == null) return;
String val = null;
for (javax.servlet.http.Cookie c : cs) {
    if ("TRUSTED_PREF".equals(c.getName())) { val = c.getValue(); break; }
}
if (val == null) return;
String out = org.owasp.encoder.Encode.forHtml(val);
response.getWriter().println(out);
    }
}
