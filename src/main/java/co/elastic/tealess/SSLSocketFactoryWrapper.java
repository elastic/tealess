package co.elastic.tealess;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;

class SSLSocketFactoryWrapper extends SSLSocketFactory {
    private final SSLSocketFactory factory;
    private static final ByteArrayInputStream emptyInputStream = new ByteArrayInputStream(new byte[0]);

    @Override
    public String[] getDefaultCipherSuites() {
        return factory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return factory.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        TLSObserver observer = new DiagnosticTLSObserver();
        return observer.observeExceptions(factory.createSocket(observer.observeIO(socket), host, port, autoClose));
    }

    @Override
    public Socket createSocket(Socket socket, InputStream inputStream, boolean autoClose) throws IOException {
        TLSObserver observer = new DiagnosticTLSObserver();
        return observer.observeExceptions(factory.createSocket(observer.observeIO(socket), inputStream, autoClose));
    }

    @Override
    public Socket createSocket() throws IOException {
        Socket socket = SocketFactory.getDefault().createSocket();
        TLSObserver observer = new DiagnosticTLSObserver();
        return observer.observeExceptions(factory.createSocket(observer.observeIO(socket), emptyInputStream, true));
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        System.out.println("createSocket 3");
        TLSObserver observer = new DiagnosticTLSObserver();
        Socket socket = SocketFactory.getDefault().createSocket(host, port);
        return observer.observeExceptions(factory.createSocket(observer.observeIO(socket), host, port, true));
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException {
        Socket socket = SocketFactory.getDefault().createSocket(host, port, localAddress, localPort);
        TLSObserver observer = new DiagnosticTLSObserver();
        return observer.observeExceptions(factory.createSocket(observer.observeIO(socket), host, port, true));
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int port) throws IOException {
        Socket socket = SocketFactory.getDefault().createSocket(inetAddress, port);
        System.out.println("createSocket 5");
        TLSObserver observer = new DiagnosticTLSObserver();
        return observer.observeExceptions(factory.createSocket(observer.observeIO(socket), inetAddress.getHostAddress(), port, true));
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1, int i1) throws IOException {
        Socket socket = SocketFactory.getDefault().createSocket(inetAddress, i, inetAddress1, i1);
        TLSObserver observer = new DiagnosticTLSObserver();
        return observer.observeExceptions(factory.createSocket(observer.observeIO(socket), emptyInputStream, true));
    }

    static SSLSocketFactory wrap(SSLSocketFactory factory) {
        return new SSLSocketFactoryWrapper(factory);
    }

    private SSLSocketFactoryWrapper(SSLSocketFactory factory) {
        this.factory = factory;
    }

}
