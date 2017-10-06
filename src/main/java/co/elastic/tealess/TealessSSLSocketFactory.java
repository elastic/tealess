package co.elastic.tealess;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;

class TealessSSLSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory factory;
    private static final ByteArrayInputStream emptyInputStream = new ByteArrayInputStream(new byte[0]);
    private final String[] cipherSuites;

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
        SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), host, port, autoClose));
        sslSocket.setEnabledCipherSuites(cipherSuites);
        //Arrays.asList(sslSocket.getSupportedCipherSuites()).stream().sorted().forEach(System.out::println);
        return sslSocket;
    }

    @Override
    public Socket createSocket(Socket socket, InputStream inputStream, boolean autoClose) throws IOException {
        TLSObserver observer = new DiagnosticTLSObserver();
        SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), inputStream, autoClose));
        sslSocket.setEnabledCipherSuites(cipherSuites);
        //Arrays.asList(sslSocket.getSupportedCipherSuites()).stream().sorted().forEach(System.out::println);
        return sslSocket;
    }

    @Override
    public Socket createSocket() throws IOException {
        TLSObserver observer = new DiagnosticTLSObserver();
        Socket socket = SocketFactory.getDefault().createSocket();
        SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), emptyInputStream, true));
        sslSocket.setEnabledCipherSuites(cipherSuites);
        //Arrays.asList(sslSocket.getSupportedCipherSuites()).stream().sorted().forEach(System.out::println);
        return sslSocket;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        TLSObserver observer = new DiagnosticTLSObserver();
        Socket socket = SocketFactory.getDefault().createSocket(host, port);
        SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), host, port, true));
        sslSocket.setEnabledCipherSuites(cipherSuites);
        //Arrays.asList(sslSocket.getSupportedCipherSuites()).stream().sorted().forEach(System.out::println);
        return sslSocket;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException {
        TLSObserver observer = new DiagnosticTLSObserver();
        Socket socket = SocketFactory.getDefault().createSocket(host, port, localAddress, localPort);
        SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), host, port, true));
        sslSocket.setEnabledCipherSuites(cipherSuites);
        //Arrays.asList(sslSocket.getSupportedCipherSuites()).stream().sorted().forEach(System.out::println);
        return sslSocket;
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int port) throws IOException {
        TLSObserver observer = new DiagnosticTLSObserver();
        Socket socket = SocketFactory.getDefault().createSocket(inetAddress, port);
        SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), inetAddress.getHostAddress(), port, true));
        sslSocket.setEnabledCipherSuites(cipherSuites);
        //Arrays.asList(sslSocket.getSupportedCipherSuites()).stream().sorted().forEach(System.out::println);
        return sslSocket;
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1, int i1) throws IOException {
        TLSObserver observer = new DiagnosticTLSObserver();
        Socket socket = SocketFactory.getDefault().createSocket(inetAddress, i, inetAddress1, i1);
        SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), emptyInputStream, true));
        sslSocket.setEnabledCipherSuites(cipherSuites);
        //Arrays.asList(sslSocket.getSupportedCipherSuites()).stream().sorted().forEach(System.out::println);
        return sslSocket;
    }

    public TealessSSLSocketFactory(SSLSocketFactory factory, String[] cipherSuites) {
        this.factory = factory;
        this.cipherSuites = cipherSuites;
    }

    public TealessSSLSocketFactory(SSLSocketFactory factory) {
        this.factory = factory;
        this.cipherSuites = getDefaultCipherSuites();
    }
}
