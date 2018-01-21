package co.elastic.tealess;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import java.io.IOException;
import java.net.*;
import java.nio.channels.ServerSocketChannel;

/**
 * Created by jls on 10/14/2017.
 */
class SSLServerSocketProxy extends SSLServerSocket {
  private SSLServerSocket server;

  SSLServerSocketProxy(SSLServerSocket server) throws IOException {
    super();
    this.server = server;
  }

  public static void setSocketFactory(SocketImplFactory fac) throws IOException {
    ServerSocket.setSocketFactory(fac);
  }

  public String[] getEnabledCipherSuites() {
    return server.getEnabledCipherSuites();
  }

  public void setEnabledCipherSuites(String[] strings) {
    server.setEnabledCipherSuites(strings);
  }

  public String[] getSupportedCipherSuites() {
    return server.getSupportedCipherSuites();
  }

  public String[] getSupportedProtocols() {
    return server.getSupportedProtocols();
  }

  public String[] getEnabledProtocols() {
    return server.getEnabledProtocols();
  }

  public void setEnabledProtocols(String[] strings) {
    server.setEnabledProtocols(strings);
  }

  public boolean getNeedClientAuth() {
    return server.getNeedClientAuth();
  }

  public void setNeedClientAuth(boolean b) {
    server.setNeedClientAuth(b);
  }

  public boolean getWantClientAuth() {
    return server.getWantClientAuth();
  }

  public void setWantClientAuth(boolean b) {
    server.setWantClientAuth(b);
  }

  public boolean getUseClientMode() {
    return server.getUseClientMode();
  }

  public void setUseClientMode(boolean b) {
    server.setUseClientMode(b);
  }

  public boolean getEnableSessionCreation() {
    return server.getEnableSessionCreation();
  }

  public void setEnableSessionCreation(boolean b) {
    server.setEnableSessionCreation(b);
  }

  public SSLParameters getSSLParameters() {
    return server.getSSLParameters();
  }

  public void setSSLParameters(SSLParameters sslParameters) {
    server.setSSLParameters(sslParameters);
  }

  public void bind(SocketAddress endpoint) throws IOException {
    server.bind(endpoint);
  }

  public void bind(SocketAddress endpoint, int backlog) throws IOException {
    server.bind(endpoint, backlog);
  }

  public InetAddress getInetAddress() {
    return server.getInetAddress();
  }

  public int getLocalPort() {
    return server.getLocalPort();
  }

  public SocketAddress getLocalSocketAddress() {
    return server.getLocalSocketAddress();
  }

  public Socket accept() throws IOException {
    return server.accept();
  }

  public void close() throws IOException {
    server.close();
  }

  public ServerSocketChannel getChannel() {
    return server.getChannel();
  }

  public boolean isBound() {
    return server.isBound();
  }

  public boolean isClosed() {
    return server.isClosed();
  }

  public int getSoTimeout() throws IOException {
    return server.getSoTimeout();
  }

  public void setSoTimeout(int timeout) throws SocketException {
    server.setSoTimeout(timeout);
  }

  public boolean getReuseAddress() throws SocketException {
    return server.getReuseAddress();
  }

  public void setReuseAddress(boolean on) throws SocketException {
    server.setReuseAddress(on);
  }

  public int getReceiveBufferSize() throws SocketException {
    return server.getReceiveBufferSize();
  }

  public void setReceiveBufferSize(int size) throws SocketException {
    server.setReceiveBufferSize(size);
  }

  public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
    server.setPerformancePreferences(connectionTime, latency, bandwidth);
  }
}
