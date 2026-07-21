package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/pathtraver-01/BenchmarkTest28362")
public class BenchmarkTest28362 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("BenchmarkTest");
        if (param == null) param = "";
String host = param;
String seg = request.getParameter("seg");
if (seg == null) seg = "home";
if (host.matches("^[a-zA-Z0-9.-]+\\.safe\\.com$")) {
    response.sendRedirect("https://" + host + "/" + seg);
}
    }
}
