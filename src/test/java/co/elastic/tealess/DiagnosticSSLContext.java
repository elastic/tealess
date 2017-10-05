package co.elastic.tealess;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import java.security.Provider;

class DiagnosticSSLContext extends SSLContext {
    private SSLContext sslContext;

    protected DiagnosticSSLContext(SSLContextSpi sslContextSpi, Provider provider, String s) {
        super(sslContextSpi, provider, s);
    }
}
