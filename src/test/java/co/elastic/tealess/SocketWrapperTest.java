package co.elastic.tealess;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class SocketWrapperTest {
    final SSLContext context;

    public SocketWrapperTest() throws KeyStoreException, KeyManagementException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, IOException {
        final SSLContextBuilder cb = new SSLContextBuilder();
        try {
            KeyStoreBuilder tb = new KeyStoreBuilder();
            tb.useKeyStore(new File("C:\\Users\\jls\\.keystore"), "foobar".toCharArray());
            cb.setTrustStore(tb.buildKeyStore());
        } catch (IOException | CertificateException | KeyStoreException | UnrecoverableKeyException e) {
            throw e;
        }
        try {
            context = new SSLContextProxy(new SSLContextSpiProxy(cb.build()), null, null);
        } catch (KeyManagementException | KeyStoreException e) {
            throw e;
        }
    }

    @Test
    public void testApacheHTTPClient() throws IOException {
        try {
            CloseableHttpClient client = HttpClients.custom().setSSLContext(context).build();
            //HttpGet get = new HttpGet("https://twitter.com/");
            HttpGet get = new HttpGet("https://192.168.1.205:9200/");
            CloseableHttpResponse response = client.execute(get);
            System.out.println(response.getStatusLine());
        } catch (IOException e) {
            System.out.println("Exception: " + e.getClass() + ": " + e);
        }
    }


    @Test
    public void testSocketFactory() throws NoSuchAlgorithmException {
        SSLSocketFactory ssf = context.getSocketFactory();
        try (Socket conn = ssf.createSocket("google.com", 443)) {
            OutputStream x = conn.getOutputStream();
            System.out.println("Stream: " + x.getClass());
            conn.getOutputStream().write("GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n".getBytes());

            byte[] b = new byte[1024];
            int c;
            while ((c = conn.getInputStream().read(b)) >= 0) {
                System.out.write(b, 0, c);
            }
            conn.close();
        } catch (IOException e1) {
            System.out.println("Exception: " + e1);
            //e1.printStackTrace();
        }
    }
}
