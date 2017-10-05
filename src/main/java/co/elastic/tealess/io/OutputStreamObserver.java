package co.elastic.tealess.io;

import java.io.IOException;
import java.io.OutputStream;

class OutputStreamObserver extends OutputStream {
    private final OutputStream stream;
    private final OutputObserver observer;
    private final ExceptionObserver exceptionObserver;

    public OutputStreamObserver(OutputStream stream, OutputObserver observer, ExceptionObserver exceptionObserver) {
        this.stream = stream;
        this.observer = observer;
        this.exceptionObserver = exceptionObserver;
    }

    @Override
    public void write(int b) throws IOException {
        try {
            stream.write(b);
        } catch (IOException e) {
            if (exceptionObserver != null) {
                exceptionObserver.exception(e);
            }
            throw e;
        }
        if (observer != null) {
            observer.write(b);
        }
    }

    @Override
    public void write(byte[] b) throws IOException {
        System.out.println("WRITE");
        try {
            stream.write(b);
        } catch (IOException e) {
            if (exceptionObserver != null) {
                exceptionObserver.exception(e);
            }
            throw e;
        }
        if (observer != null) {
            observer.write(b);
        }
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        try {
            stream.write(b, off, len);
        } catch (IOException e) {
            if (exceptionObserver != null) {
                exceptionObserver.exception(e);
            }
            throw e;
        }
        if (observer != null) {
            observer.write(b, off, len);
        }
    }

    @Override
    public void flush() throws IOException {
        stream.flush();
    }

    @Override
    public void close() throws IOException {
        stream.close();
    }
}
