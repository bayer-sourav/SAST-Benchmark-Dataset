/**
 * OWASP Benchmark Project v1.2
 *
 * @author Nick Sanidas
 * @created 2015
 */
package org.owasp.benchmark.testcode.blcurated;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/benchmark/err/BlCurated00217")
public class BlCurated00217 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("BlCurated00217");
        if (param == null) {
            param = "";
        }
try {
    int x = Integer.parseInt(param);
    response.getWriter().println("ok " + x);
} catch (Exception e) {
    String safe = org.springframework.web.util.HtmlUtils.htmlEscape(e.getMessage());
    if ("true".equals(request.getParameter("debug"))) {
        response.getWriter().println(java.util.Arrays.toString(e.getStackTrace()));
    } else {
        response.getWriter().println("error: " + safe);
    }
}
    }
}
