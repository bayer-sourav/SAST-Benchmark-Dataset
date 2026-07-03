package org.owasp.benchmark.testcode.blv4;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/benchmark/blv4/dns/BlV4_00161")
public class BlV4_00161 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("data");
        if (param == null) param = "";
String target = param;
java.net.InetAddress addr = java.net.InetAddress.getByName(target);
if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()) return;
java.net.URL url = new java.net.URL("http://" + target + "/api");
url.openStream();
    }
}
