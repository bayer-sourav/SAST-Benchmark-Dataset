package org.owasp.benchmark.testcode;

    import java.io.IOException;
    import javax.servlet.ServletException;
    import javax.servlet.annotation.WebServlet;
    import javax.servlet.http.HttpServlet;
    import javax.servlet.http.HttpServletRequest;
    import javax.servlet.http.HttpServletResponse;

    @WebServlet(value = "/pathtraver-02/BenchmarkTest28523")
    public class BenchmarkTest28523 extends HttpServlet {
        private static final long serialVersionUID = 1L;

private static boolean isNonPublicAddress(java.net.InetAddress addr) {
    return addr.isLoopbackAddress() || addr.isSiteLocalAddress()
            || addr.isLinkLocalAddress() || addr.isAnyLocalAddress();
}

private static java.net.InetAddress resolveHost(String host) throws java.net.UnknownHostException {
    return java.net.InetAddress.getByName(host);
}

private void fetchHttpByHostname(String host) throws java.io.IOException {
    new java.net.URL("http://" + host + "/api").openStream();
}

private void connectHttpByHostname(String host) throws java.io.IOException {
    new java.net.URL("http://" + host).openConnection().connect();
}

private void openUrlByHostname(String host) throws java.io.IOException {
    new java.net.URL("https://" + host + "/health").openStream();
}

        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            response.setContentType("text/html;charset=UTF-8");
            String param = request.getParameter("BenchmarkTest");
            if (param == null) param = "";
String host = param;
java.net.InetAddress addr = resolveHost(host);
if (isNonPublicAddress(addr)) return;
addr.getHostName();
openUrlByHostname(host);
    }
}
