package org.owasp.benchmark.testcode.blv4;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/benchmark/blv4/semi/BlV4_00362")
public class BlV4_00362 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("data");
        if (param == null) param = "";
String pat = getServletContext().getInitParameter("safe.pattern");
if (param.matches(pat)) {
    response.getWriter().println(param);
}
    }
}
