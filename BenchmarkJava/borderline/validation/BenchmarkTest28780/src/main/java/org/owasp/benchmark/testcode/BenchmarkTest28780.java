package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/xss-04/BenchmarkTest28780")
public class BenchmarkTest28780 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("BenchmarkTest");
        if (param == null) param = "";
String state = request.getParameter("state");
if (state == null) return;
String redirect = (String) request.getSession().getAttribute("oauth_state_" + state);
if (redirect != null && redirect.startsWith("/")) {
    response.sendRedirect(redirect);
}
    }
}
