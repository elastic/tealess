package co.elastic.tealess.io;

import java.io.IOException;
import java.io.InputStream;

class InputStreamObserver extends InputStream {
    private final InputObserver observer;
    private final InputStream stream;
    private final ExceptionObserver exceptionObserver;

    public InputStreamObserver(InputStream stream, InputObserver observer, ExceptionObserver exceptionObserver) {
        this.observer = observer;
        this.stream = stream;
        this.exceptionObserver = exceptionObserver;
    }

    @Override
    public int read() throws IOException {
        try {
            int i = stream.read();
            observer.read(i);
            return i;
        } catch (IOException e) {
            if (exceptionObserver != null) {
                exceptionObserver.exception(e);
            }
            throw e;
        }
    }

    @Override
    public int read(byte[] b) throws IOException {
        try {
            int i = stream.read(b);
            observer.read(b, i);
            return i;
        } catch (IOException e) {
            if (exceptionObserver != null) {
                exceptionObserver.exception(e);
            }
            throw e;
        }
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        try {
            int i = stream.read(b, off, len);
            observer.read(b, off, len, i);
            return i;
        } catch (IOException e) {
            if (exceptionObserver != null) {
                exceptionObserver.exception(e);
            }
            throw e;
        }
    }

    @Override
    public long skip(long n) throws IOException {
        return stream.skip(n);
    }

    @Override
    public int available() throws IOException {
        return stream.available();
    }

    @Override
    public void close() throws IOException {
        stream.close();
    }

    @Override
    public void mark(int readlimit) {
        stream.mark(readlimit);
    }

    @Override
    public void reset() throws IOException {
        stream.reset();
    }

    @Override
    public boolean markSupported() {
        return stream.markSupported();
    }
}
