package co.elastic.tealess;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class ObservableX509ExtendedTrustManager extends X509ExtendedTrustManagerProxy {
    private final Logger logger = LogManager.getLogger();

    public ObservableX509ExtendedTrustManager(X509ExtendedTrustManager trustManager) {
        super(trustManager);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        logger.trace("checkServerTrusted: host:{}, certs:{}", s, x509Certificates);
        super.checkServerTrusted(x509Certificates, s, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        logger.trace("checkClientTrusted: host:{}, certs:{}", s, x509Certificates);
        super.checkClientTrusted(x509Certificates, s, socket);
    }
}
