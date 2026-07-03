package org.owasp.benchmark.testcode.blv4;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/benchmark/blv4/dns/BlV4_00166")
public class BlV4_00166 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("data");
        if (param == null) param = "";
String u = param;
if (!u.contains("127.0.0.1") && !u.contains("localhost")) {
    java.net.InetAddress a = java.net.InetAddress.getByName(new java.net.URL(u).getHost());
    if (!a.isAnyLocalAddress()) {
        new java.net.URL(u).openStream();
    }
}
    }
}
