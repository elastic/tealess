package co.elastic.tealess;

import co.elastic.tealess.io.BufferUtil;
import co.elastic.tealess.io.Transaction;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;

public class TealessSSLEngine extends SSLEngineProxy {
    private final String[] cipherSuites;
    private final TrustManager[] trustManagers;

    private final List<Transaction<?>> log = new LinkedList<>();
    private final ByteBuffer input = ByteBuffer.allocate(16384);
    private final ByteBuffer output = ByteBuffer.allocate(16384);
    private boolean outputFull = false;
    private boolean inputFull = false;


    public TealessSSLEngine(SSLEngine engine, String[] cipherSuites, TrustManager[] trustManagers) {
        super(engine);

        this.cipherSuites = cipherSuites;
        this.trustManagers = trustManagers;
    }

    private void recordOutput(ByteBuffer buffer) {
        if (!outputFull && buffer.position() > 0) {
            final ByteBuffer dup = buffer.duplicate();
            dup.position(0);
            dup.limit(buffer.position());
            log.add(Transaction.create(Transaction.Operation.Output, dup.remaining()));
            try {
                output.put(dup);
            } catch (BufferOverflowException e) {
                outputFull = true;
            }
        }
    }

    private void recordInput(ByteBuffer buffer) {
        if (!inputFull && buffer.remaining() > 0) {
            System.out.printf("input %s %d\n", buffer, buffer.remaining());
            buffer.mark();
            log.add(Transaction.create(Transaction.Operation.Input, buffer.remaining()));
            try {
                input.put(buffer);
            } catch (BufferOverflowException e) {
                inputFull = true;
            } finally {
                buffer.reset();
            }
        }
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer srcs, ByteBuffer dst) throws SSLException {
        try {
            SSLEngineResult result = super.wrap(srcs, dst);
            if (!outputFull) {
                recordOutput(dst);
            }
            return result;
        } catch (SSLException e) {
            DiagnosticTLSObserver.diagnoseException(log, input, output, e, trustManagers);
            throw e;
        }
    }


    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, ByteBuffer dst) throws SSLException {
        try {
            SSLEngineResult result = super.wrap(srcs, dst);
            if (!outputFull) {
                recordOutput(dst);
            }
            return result;
        } catch (SSLException e) {
            DiagnosticTLSObserver.diagnoseException(log, input, output, e, trustManagers);
            throw e;
        }
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int i, int i1, ByteBuffer dst) throws SSLException {
        try {
            SSLEngineResult result = super.wrap(srcs, i, i1, dst);
            if (!outputFull) {
                recordOutput(dst);
            }
            return result;
        } catch (SSLException e) {
            DiagnosticTLSObserver.diagnoseException(log, input, output, e, trustManagers);
            throw e;
        }
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        if (!inputFull) {
            recordInput(src);
        }
        try {
            return super.unwrap(src, dst);
        } catch (SSLException e) {
            DiagnosticTLSObserver.diagnoseException(log, input, output, e, trustManagers);
            throw e;
        }
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException {
        if (!inputFull) {
            recordInput(src);
        }
        try {
            return super.unwrap(src, dsts);
        } catch (SSLException e) {
            DiagnosticTLSObserver.diagnoseException(log, input, output, e, trustManagers);
            throw e;
        }
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int i, int i1) throws SSLException {
        if (!inputFull) {
            recordInput(src);
        }
        try {
            return super.unwrap(src, dsts, i, i1);
        } catch (SSLException e) {
            DiagnosticTLSObserver.diagnoseException(log, input, output, e, trustManagers);
            throw e;
        }
    }

}
