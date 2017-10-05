package co.elastic.tealess;

import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class SocketWrapperTest {
    @Test
    public void test() throws NoSuchAlgorithmException {
        final SSLContext context;
        final SSLContextBuilder cb = new SSLContextBuilder();
        try {
            KeyStoreBuilder tb = new KeyStoreBuilder();
            tb.useKeyStore(new File("C:\\Users\\jls\\.keystore"), "foobar".toCharArray());
            cb.setTrustStore(tb.buildKeyStore());
        } catch (IOException | CertificateException | KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
            return;
        }
        try {
            context = cb.build();
        } catch (KeyManagementException | KeyStoreException e) {
            e.printStackTrace();
            return;
        }

        SSLSocketFactory ssf = SSLSocketFactoryWrapper.wrap(context.getSocketFactory());
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
