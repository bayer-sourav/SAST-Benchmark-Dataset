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

@WebServlet(value = "/benchmark/sqli/BlCurated00123")
public class BlCurated00123 extends HttpServlet {
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
        String param = request.getParameter("BlCurated00123");
        if (param == null) {
            param = "";
        }
String bar = param.replace("'", "''");
java.sql.Connection conn = null;
try {
    javax.naming.InitialContext ctx = new javax.naming.InitialContext();
    conn = ((javax.sql.DataSource) ctx.lookup("java:comp/env/jdbc/BenchmarkDB")).getConnection();
    String sql = "SELECT * FROM USERS WHERE name = '" + bar + "'";
    conn.createStatement().executeQuery(sql);
} finally {
    if (conn != null) try { conn.close(); } catch (Exception e) {}
}
    }
}
