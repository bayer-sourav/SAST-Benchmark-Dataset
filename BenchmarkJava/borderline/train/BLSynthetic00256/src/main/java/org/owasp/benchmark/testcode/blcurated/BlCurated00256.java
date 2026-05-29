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

@WebServlet(value = "/benchmark/rand/BlCurated00256")
public class BlCurated00256 extends HttpServlet {
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
        String param = request.getParameter("BlCurated00256");
        if (param == null) {
            param = "";
        }
byte[] bytes = new byte[16];
java.security.SecureRandom sr = new java.security.SecureRandom();
sr.setSeed(param.getBytes("UTF-8"));
sr.nextBytes(bytes);
String token = javax.xml.bind.DatatypeConverter.printHexBinary(bytes);
response.getWriter().println("token=" + token);
    }
}
