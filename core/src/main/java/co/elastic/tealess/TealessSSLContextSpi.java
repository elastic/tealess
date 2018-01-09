package co.elastic.tealess;

import javax.net.ssl.*;
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
        return new TealessSSLEngine(super.engineCreateSSLEngine(), cipherSuites, trustManagers);
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        return new TealessSSLEngine(super.engineCreateSSLEngine(host, port), cipherSuites, trustManagers);
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return new TealessSSLServerSocketFactory(super.engineGetServerSocketFactory(), cipherSuites, trustManagers);
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
