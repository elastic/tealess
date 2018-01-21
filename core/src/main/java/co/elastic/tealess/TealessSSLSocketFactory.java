package co.elastic.tealess;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;

class TealessSSLSocketFactory extends SSLSocketFactory {
  private static final ByteArrayInputStream emptyInputStream = new ByteArrayInputStream(new byte[0]);
  private final SSLSocketFactory factory;
  private final String[] cipherSuites;
  private final TrustManager[] trustManagers;

  public TealessSSLSocketFactory(SSLSocketFactory factory, String[] cipherSuites, TrustManager[] trustManagers) {
    this.factory = factory;
    this.cipherSuites = cipherSuites;
    this.trustManagers = trustManagers;
  }

  private void setEnabledCipherSuites(SSLSocket sslSocket) {
    try {
      sslSocket.setEnabledCipherSuites(cipherSuites);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(e.getMessage() + ". Supported ciphersuites are: " + Arrays.asList(sslSocket.getSupportedCipherSuites()), e);
    }
  }

  private TLSObserver newObserver() {
    return new DiagnosticTLSObserver(trustManagers);
  }


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
    TLSObserver observer = newObserver();
    SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), host, port, autoClose));
    setEnabledCipherSuites(sslSocket);
    return sslSocket;
  }

  @Override
  public Socket createSocket(Socket socket, InputStream inputStream, boolean autoClose) throws IOException {
    TLSObserver observer = newObserver();
    SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), inputStream, autoClose));
    setEnabledCipherSuites(sslSocket);
    return sslSocket;
  }

  @Override
  public Socket createSocket() throws IOException {
    Socket socket = SocketFactory.getDefault().createSocket();

    TLSObserver observer = newObserver();
    SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), emptyInputStream, true));
    setEnabledCipherSuites(sslSocket);
    return sslSocket;
  }

  @Override
  public Socket createSocket(String host, int port) throws IOException {
    Socket socket = SocketFactory.getDefault().createSocket(host, port);

    TLSObserver observer = newObserver();
    SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), host, port, true));
    setEnabledCipherSuites(sslSocket);
    return sslSocket;
  }

  @Override
  public Socket createSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException {
    Socket socket = SocketFactory.getDefault().createSocket(host, port, localAddress, localPort);

    TLSObserver observer = newObserver();
    SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), host, port, true));
    setEnabledCipherSuites(sslSocket);
    return sslSocket;
  }

  @Override
  public Socket createSocket(InetAddress host, int port) throws IOException {
    Socket socket = SocketFactory.getDefault().createSocket(host, port);

    TLSObserver observer = newObserver();
    SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), host.getHostAddress(), port, true));
    setEnabledCipherSuites(sslSocket);
    return sslSocket;
  }

  @Override
  public Socket createSocket(InetAddress host, int port, InetAddress localAddress, int localPort) throws IOException {
    Socket socket = SocketFactory.getDefault().createSocket(host, port, localAddress, localPort);

    TLSObserver observer = newObserver();
    SSLSocket sslSocket = observer.observeExceptions((SSLSocket) factory.createSocket(observer.observeIO(socket), emptyInputStream, true));
    setEnabledCipherSuites(sslSocket);
    return sslSocket;
  }

}
