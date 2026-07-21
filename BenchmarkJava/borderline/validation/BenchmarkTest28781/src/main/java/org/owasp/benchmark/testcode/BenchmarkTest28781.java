package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/xss-00/BenchmarkTest28781")
public class BenchmarkTest28781 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("BenchmarkTest");
        if (param == null) param = "";
Object v = request.getSession().getAttribute("partnerCallback");
if (v == null) return;
String url = v.toString();
String suffix = getServletContext().getInitParameter("partner.domain.suffix");
if (url.startsWith("https://") && suffix != null && url.contains(suffix)) {
    response.sendRedirect(url);
}
    }
}
