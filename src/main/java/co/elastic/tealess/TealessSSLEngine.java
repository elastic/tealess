package co.elastic.tealess;

import co.elastic.tealess.io.Transaction;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;

public class TealessSSLEngine extends SSLEngineProxy {
    private final String[] cipherSuites;
    private final TrustManager[] trustManagers;

    private final List<Transaction<?>> log = new LinkedList<>();
    private final ByteBuffer input = ByteBuffer.allocate(16384);
    private final ByteBuffer output = ByteBuffer.allocate(16384);


    public TealessSSLEngine(SSLEngine engine, String[] cipherSuites, TrustManager[] trustManagers) {
        super(engine);

        this.cipherSuites = cipherSuites;
        this.trustManagers = trustManagers;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer srcs, ByteBuffer dst) throws SSLException {
        System.out.println("wrap1");
        return super.wrap(srcs, dst);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, ByteBuffer dst) throws SSLException {
        for (int i = 0; i < srcs.length; i ++) {
            log.add(Transaction.create(Transaction.Operation.Output, srcs[i].remaining()));
            srcs[i].mark();
            output.put(srcs[i]);
            srcs[i].reset();
        }
        System.out.println("wrap2");
        return super.wrap(srcs, dst);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int i, int i1, ByteBuffer dst) throws SSLException {
        System.out.println("wrap3");
        return super.wrap(srcs, i, i1, dst);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        // unwrapping == input from remote
        System.out.println("unwrap1");
        log.add(Transaction.create(Transaction.Operation.Input, src.remaining()));
        src.mark();
        input.put(src);
        src.reset();
        try {
            return super.unwrap(src, dst);
        } catch (SSLException e) {
            DiagnosticTLSObserver.diagnoseException(log, input, output, e, trustManagers);
            throw e;
        }
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException {
        System.out.println("unwrap2");
        return super.unwrap(src, dsts);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int i, int i1) throws SSLException {
        System.out.println("unwrap3");
        return super.unwrap(src, dsts, i, i1);
    }

}
