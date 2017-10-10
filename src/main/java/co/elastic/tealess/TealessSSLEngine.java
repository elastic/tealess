package co.elastic.tealess;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import java.nio.ByteBuffer;

public class TealessSSLEngine extends SSLEngineProxy {
    private final String[] cipherSuites;
    private final TrustManager[] trustManagers;

    public TealessSSLEngine(SSLEngine engine, String[] cipherSuites, TrustManager[] trustManagers) {
        super(engine);
        this.cipherSuites = cipherSuites;
        this.trustManagers = trustManagers;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer byteBuffer, ByteBuffer byteBuffer1) throws SSLException {
        System.out.println("wrap1");
        return super.wrap(byteBuffer, byteBuffer1);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] byteBuffers, ByteBuffer byteBuffer) throws SSLException {
        System.out.println("wrap2");
        return super.wrap(byteBuffers, byteBuffer);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] byteBuffers, int i, int i1, ByteBuffer byteBuffer) throws SSLException {
        System.out.println("wrap3");
        return super.wrap(byteBuffers, i, i1, byteBuffer);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer byteBuffer, ByteBuffer byteBuffer1) throws SSLException {
        System.out.println("unwrap1");
        return super.unwrap(byteBuffer, byteBuffer1);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer byteBuffer, ByteBuffer[] byteBuffers) throws SSLException {
        System.out.println("unwrap2");
        return super.unwrap(byteBuffer, byteBuffers);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer byteBuffer, ByteBuffer[] byteBuffers, int i, int i1) throws SSLException {
        System.out.println("unwrap3");
        return super.unwrap(byteBuffer, byteBuffers, i, i1);
    }
}
