package co.elastic.tealess;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

public class SSLContextSpiProxy extends SSLContextSpi {
    private final String[] cipherSuites;
    private SSLContext context;

    public SSLContextSpiProxy(SSLContext context, String[] cipherSuites) {
        this.context = context;
        this.cipherSuites = cipherSuites;
    }

    @Override
    protected void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) throws KeyManagementException {
        System.out.printf("k: %s, t: %s\n", keyManagers, trustManagers);
        for (TrustManager trustManager : trustManagers) {
            X509TrustManager x509trust = (X509TrustManager) trustManager;
            for (X509Certificate x509Certificate : x509trust.getAcceptedIssuers()) {
                System.out.println("Trusted: " + x509Certificate.getSubjectX500Principal());
            }
        }
        context.init(keyManagers, trustManagers, secureRandom);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        return new TealessSSLSocketFactory(context.getSocketFactory(), cipherSuites);
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return context.getServerSocketFactory();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return context.createSSLEngine();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        return context.createSSLEngine(host, port);
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return context.getServerSessionContext();
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return context.getClientSessionContext();
    }
}
