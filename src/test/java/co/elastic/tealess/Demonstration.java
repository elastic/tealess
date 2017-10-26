package co.elastic.tealess;

import co.elastic.tealess.tls.CipherSuite;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;

public class Demonstration {
    private final SSLContextBuilder contextBuilder = new SSLContextBuilder();
    private SSLContext defaultContext;

    private TrustManagerFactory tmf;

    public Demonstration() throws NoSuchAlgorithmException {
        tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        defaultContext = SSLContext.getInstance("TLS");
    }

    @Test(expected = SSLHandshakeException.class)
    public void ancientCipher() throws IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        contextBuilder.setCipherSuites(new String[]{CipherSuite.TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5.name()});
        SSLContext context = contextBuilder.build();

        tryHTTP(context);
    }

    @Test(expected = SSLHandshakeException.class)
    public void untrustedCertificate() throws IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, CertificateException, UnrecoverableKeyException {
        String keystorePath = SocketWrapperTest.class.getClassLoader().getResource("keystore.jks").getPath();
        KeyStoreBuilder trust = new KeyStoreBuilder();
        trust.useKeyStore(new File(keystorePath), "password".toCharArray());
        contextBuilder.setTrustStore(trust.buildKeyStore());
        SSLContext context = contextBuilder.build();

        tryHTTP(context);
    }

    @Test(expected = SSLHandshakeException.class)
    public void defaultSSLContextUntrustedCertificate() throws IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, CertificateException, UnrecoverableKeyException {
        String keystorePath = SocketWrapperTest.class.getClassLoader().getResource("keystore.jks").getPath();
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystorePath), "password".toCharArray());
        tmf.init(ks);
        defaultContext.init(null, tmf.getTrustManagers(), null);

        tryHTTP(defaultContext);
    }

    private void tryHTTP(SSLContext context) throws IOException {
        // Get an HTTP Client using our SSLContext.
        CloseableHttpClient client = HttpClients.custom().setSSLContext(context).build();

        // Fetch twitter's main page.
        HttpGet get = new HttpGet("https://twitter.com/");
        CloseableHttpResponse response = client.execute(get);
        System.out.println(response.getStatusLine());
    }

    private void trySocket(SSLContext context) throws IOException {
        SSLSocketFactory ssf = context.getSocketFactory();
        try (Socket conn = ssf.createSocket("google.com", 443)) {
            OutputStream x = conn.getOutputStream();
            conn.getOutputStream().write("GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n".getBytes());

            // Drain the connection
            byte[] b = new byte[1024];
            int c;
            while ((c = conn.getInputStream().read(b)) >= 0) {
                System.out.write(b, 0, c);
            }
            conn.close();
        }
    }
}
