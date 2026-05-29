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

@WebServlet(value = "/benchmark/xss/BlCurated00065")
public class BlCurated00065 extends HttpServlet {
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
        String param = request.getParameter("BlCurated00065");
        if (param == null) {
            param = "";
        }
String bar = param;
if (false) {
    bar = org.springframework.web.util.HtmlUtils.htmlEscape(bar);
}
response.getWriter().println(bar);
    }
}
