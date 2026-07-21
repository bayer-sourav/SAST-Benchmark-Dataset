package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/sqli-03/BenchmarkTest28419")
public class BenchmarkTest28419 extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = request.getParameter("BenchmarkTest");
        if (param == null) param = "";
if (param.matches("^[a-zA-Z][a-zA-Z0-9_]*$")) {
    String sql = "SELECT * FROM " + param + " WHERE active=1";
    java.sql.Connection con = (java.sql.Connection) request.getAttribute("dbConn");
    if (con != null) {
        java.sql.Statement st = con.createStatement();
        st.executeQuery(sql);
    }
}
    }
}
