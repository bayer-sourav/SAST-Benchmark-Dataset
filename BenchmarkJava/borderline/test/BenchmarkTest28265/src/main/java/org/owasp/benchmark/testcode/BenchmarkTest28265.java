package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/pathtraver-04/BenchmarkTest28265")
public class BenchmarkTest28265 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("BenchmarkTest");
        if (param == null) param = "";
String pat = getServletContext().getInitParameter("file.pattern");
if (pat != null && param.matches(pat)) {
    java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/data/" + param));
    response.getWriter().println("ok");
}
    }
}
