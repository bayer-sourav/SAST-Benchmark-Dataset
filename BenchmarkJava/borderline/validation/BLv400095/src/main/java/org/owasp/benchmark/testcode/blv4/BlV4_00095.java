package org.owasp.benchmark.testcode.blv4;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/benchmark/blv4/dns/BlV4_00095")
public class BlV4_00095 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("data");
        if (param == null) param = "";
String host = param;
String ip = java.net.InetAddress.getByName(host).getHostAddress();
if (ip.startsWith("10.")) return;
Thread.sleep(50);
new java.net.URL("http://" + host).openConnection().connect();
    }
}
