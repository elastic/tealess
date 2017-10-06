package co.elastic.tealess;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLSocketFactory;
import java.security.Provider;

class TealessSSLContext extends SSLContext {
    TealessSSLContext(SSLContext context, String[] enabledCipherSuites) {
        this(new SSLContextSpiProxy(context, enabledCipherSuites), null, null);
    }

    // required as a subclass for SSLContext
    protected TealessSSLContext(SSLContextSpi sslContextSpi, Provider provider, String s) {
        super(sslContextSpi, provider, s);
    }

}
