package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/pathtraver-02/BenchmarkTest28453")
public class BenchmarkTest28453 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("BenchmarkTest");
        if (param == null) param = "";
String once = java.net.URLDecoder.decode(param, "UTF-8");
java.nio.file.Path base = java.nio.file.Paths.get("/data").toAbsolutePath().normalize();
java.nio.file.Path resolved = base.resolve(once).normalize();
if (resolved.startsWith(base)) {
    java.nio.file.Files.readAllBytes(resolved);
    response.getWriter().println("ok");
}
    }
}
