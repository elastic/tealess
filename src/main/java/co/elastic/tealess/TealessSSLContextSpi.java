package co.elastic.tealess;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.security.KeyManagementException;
import java.security.SecureRandom;

public class TealessSSLContextSpi extends SSLContextSpiProxy {
    private final String[] cipherSuites;
    private TrustManager[] trustManagers;

    // Wants: ciphers
    public TealessSSLContextSpi(SSLContext context, String[] cipherSuites) {
        super(context);
        this.cipherSuites = cipherSuites;
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        System.out.println("engineCreateSSLEngine");
        return new TealessSSLEngine(super.engineCreateSSLEngine(), cipherSuites, trustManagers);
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        System.out.println("engineCreateSSLEngine2");
        return super.engineCreateSSLEngine(host, port);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        return new TealessSSLSocketFactory(super.engineGetSocketFactory(), cipherSuites, trustManagers);
    }

    @Override
    protected void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) throws KeyManagementException {
        super.engineInit(keyManagers, trustManagers, secureRandom);
        this.trustManagers = trustManagers;
    }
}
