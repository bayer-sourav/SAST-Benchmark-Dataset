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

@WebServlet(value = "/benchmark/cookie/BlCurated00242")
public class BlCurated00242 extends HttpServlet {
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
        String param = request.getParameter("BlCurated00242");
        if (param == null) {
            param = "";
        }
String value = param;
if (value.length() > 128) {
    value = value.substring(0, 128);
}
javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SESSION", value);
cookie.setHttpOnly(true);
cookie.setSecure(false);
cookie.setPath("/internal/");
response.addCookie(cookie);
    }
}
