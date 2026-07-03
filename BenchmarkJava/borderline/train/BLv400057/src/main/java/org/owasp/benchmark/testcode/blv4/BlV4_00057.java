package org.owasp.benchmark.testcode.blv4;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/benchmark/blv4/bypass/BlV4_00057")
public class BlV4_00057 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("data");
        if (param == null) param = "";
String bar = param.replace("'", "''");
String sql = "SELECT * FROM users WHERE name='" + bar + "'";
java.sql.Connection con = (java.sql.Connection) request.getAttribute("dbConn");
if (con != null) {
    java.sql.Statement st = con.createStatement();
    st.executeQuery(sql);
}
    }
}
