package co.elastic.tealess;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import java.security.Provider;

public class TealessSSLContext extends SSLContext {
    // required as a subclass for SSLContext
    protected TealessSSLContext(SSLContextSpi sslContextSpi, Provider provider, String s) {
        super(sslContextSpi, provider, s);
    }

    public static SSLContext create(SSLContextSpi sslContextSpi, Provider provider, String s) {
        return new TealessSSLContext(sslContextSpi, provider, s);
    }
}
