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

@WebServlet(value = "/benchmark/ldap/BlCurated00232")
public class BlCurated00232 extends HttpServlet {
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
        String param = request.getParameter("BlCurated00232");
        if (param == null) {
            param = "";
        }
String bar = param.replace("*", "\\2a").replace("(", "\\28").replace(")", "\\29");
String filter = "(uid=" + bar + ")";
javax.naming.directory.DirContext ctx = null;
try {
    java.util.Hashtable<String, String> env = new java.util.Hashtable<>();
    env.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    env.put(javax.naming.Context.PROVIDER_URL, "ldap://localhost:389");
    ctx = new javax.naming.directory.InitialDirContext(env);
    ctx.search("ou=users", filter, new javax.naming.directory.SearchControls());
} catch (Exception e) {
    response.getWriter().println("ldap error");
} finally {
    if (ctx != null) try { ctx.close(); } catch (Exception e) {}
}
    }
}
