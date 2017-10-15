package co.elastic.tealess;

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.SecureRandom;

public class SSLContextSpiProxy extends SSLContextSpi {
    private final SSLContext context;

    public SSLContextSpiProxy(SSLContext context) {
        this.context = context;
    }

    @Override
    protected SSLParameters engineGetDefaultSSLParameters() {
        return context.getDefaultSSLParameters();
    }

    @Override
    protected SSLParameters engineGetSupportedSSLParameters() {
        return context.getSupportedSSLParameters();
    }

    @Override
    protected void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) throws KeyManagementException {
        context.init(keyManagers, trustManagers, secureRandom);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        return context.getSocketFactory();
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
