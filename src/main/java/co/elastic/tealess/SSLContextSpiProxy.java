package co.elastic.tealess;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.security.KeyManagementException;
import java.security.SecureRandom;

public class SSLContextSpiProxy extends SSLContextSpi {
    private final String[] cipherSuites;
    private SSLContext context;

    public SSLContextSpiProxy(SSLContext context, String[] cipherSuites) {
        this.context = context;
        this.cipherSuites = cipherSuites;
    }

    @Override
    protected void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) throws KeyManagementException {
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
