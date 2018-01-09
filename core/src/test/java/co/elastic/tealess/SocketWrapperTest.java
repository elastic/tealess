package co.elastic.tealess;

import co.elastic.tealess.tls.CipherSuite;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class SocketWrapperTest {
    final SSLContextBuilder contextBuilder = new SSLContextBuilder();

    @Test
    public void ancientCipherWithApache() throws IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        contextBuilder.setCipherSuites(new String[]{CipherSuite.TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5.name()});
        SSLContext context = contextBuilder.build();

        testException(context, SSLHandshakeException.class, Pattern.compile("^.*The remote server terminated our handshake attempt.*$", Pattern.DOTALL));
    }

    @Test
    public void untrustedServer() throws IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, CertificateException, UnrecoverableKeyException {
        String keystorePath = SocketWrapperTest.class.getClassLoader().getResource("keystore.jks").getPath();
        KeyStoreBuilder trust = new KeyStoreBuilder();
        trust.useKeyStore(new File(keystorePath), "garbage".toCharArray());
        contextBuilder.setTrustStore(trust.buildKeyStore());
        SSLContext context = contextBuilder.build();

        testException(context, SSLHandshakeException.class, Pattern.compile("^.*The remote server provided an unknown/untrusted certificate chain.*$", Pattern.DOTALL));
    }

    private void testException(SSLContext context, Class<? extends Throwable> exceptionClass, Pattern messagePattern) throws IOException {
        try {
            tryApache(context);
            fail("Expected a " + exceptionClass + " exception, but none was thrown.");
        } catch (IOException e) {
            System.out.println(e);
            //e.printStackTrace();
            assertEquals(e.getClass(), exceptionClass);
            Matcher matcher = messagePattern.matcher(e.getMessage());
            assertThat("Exception message, '" + e.getMessage() + "' must match " + messagePattern, matcher.matches(), is(true));

        }

        try {
            trySocket(context);
            fail("Expected a " + exceptionClass + " exception, but none was thrown.");
        } catch (IOException e) {
            assertEquals(e.getClass(), exceptionClass);
            Matcher matcher = messagePattern.matcher(e.getMessage());
            assertThat("Exception message, '" + e.getMessage() + "' must match " + messagePattern, matcher.matches(), is(true));

        }
    }

    private void tryApache(SSLContext context) throws IOException {
        CloseableHttpClient client = HttpClients.custom().setSSLContext(context).build();
        HttpGet get = new HttpGet("https://twitter.com/");
        //HttpGet get = new HttpGet("https://192.168.1.205:9200/");
        CloseableHttpResponse response = client.execute(get);
        System.out.println(response.getStatusLine());
    }

    private void trySocket(SSLContext context) throws IOException {
        SSLSocketFactory ssf = context.getSocketFactory();
        try (Socket conn = ssf.createSocket("google.com", 443)) {
            OutputStream x = conn.getOutputStream();
            conn.getOutputStream().write("GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n".getBytes());

            byte[] b = new byte[1024];
            int c;
            while ((c = conn.getInputStream().read(b)) >= 0) {
                System.out.write(b, 0, c);
            }
            conn.close();
        }
    }
}
