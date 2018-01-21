package co.elastic.tealess.io;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;

class SSLSocketProxy extends SSLSocket {
  private final SSLSocket socket;

  SSLSocketProxy(SSLSocket socket) {
    this.socket = socket;
  }

  @Override
  public String[] getSupportedCipherSuites() {
    return socket.getSupportedCipherSuites();
  }

  @Override
  public String[] getEnabledCipherSuites() {
    return socket.getEnabledCipherSuites();
  }

  @Override
  public void setEnabledCipherSuites(String[] strings) {
    socket.setEnabledCipherSuites(strings);
  }

  @Override
  public String[] getSupportedProtocols() {
    return socket.getSupportedProtocols();
  }

  @Override
  public String[] getEnabledProtocols() {
    return socket.getEnabledProtocols();
  }

  @Override
  public void setEnabledProtocols(String[] strings) {
    socket.setEnabledProtocols(strings);
  }

  @Override
  public SSLSession getSession() {
    return socket.getSession();
  }

  @Override
  public SSLSession getHandshakeSession() {
    return socket.getHandshakeSession();
  }

  @Override
  public void addHandshakeCompletedListener(HandshakeCompletedListener handshakeCompletedListener) {
    socket.addHandshakeCompletedListener(handshakeCompletedListener);
  }

  @Override
  public void removeHandshakeCompletedListener(HandshakeCompletedListener handshakeCompletedListener) {
    socket.removeHandshakeCompletedListener(handshakeCompletedListener);
  }

  @Override
  public void startHandshake() throws IOException {
    socket.startHandshake();
  }

  @Override
  public boolean getUseClientMode() {
    return socket.getUseClientMode();
  }

  @Override
  public void setUseClientMode(boolean b) {
    socket.setUseClientMode(b);
  }

  @Override
  public boolean getNeedClientAuth() {
    return socket.getNeedClientAuth();
  }

  @Override
  public void setNeedClientAuth(boolean b) {
    socket.setNeedClientAuth(b);
  }

  @Override
  public boolean getWantClientAuth() {
    return socket.getWantClientAuth();
  }

  @Override
  public void setWantClientAuth(boolean b) {
    socket.setWantClientAuth(b);
  }

  @Override
  public boolean getEnableSessionCreation() {
    return socket.getEnableSessionCreation();
  }

  @Override
  public void setEnableSessionCreation(boolean b) {
    socket.setEnableSessionCreation(b);
  }

  @Override
  public SSLParameters getSSLParameters() {
    return socket.getSSLParameters();
  }

  @Override
  public void setSSLParameters(SSLParameters sslParameters) {
    socket.setSSLParameters(sslParameters);
  }

  @Override
  public void connect(SocketAddress endpoint) throws IOException {
    socket.connect(endpoint);
  }

  @Override
  public void connect(SocketAddress endpoint, int timeout) throws IOException {
    socket.connect(endpoint, timeout);
  }

  @Override
  public void bind(SocketAddress bindpoint) throws IOException {
    socket.bind(bindpoint);
  }

  @Override
  public InetAddress getInetAddress() {
    return socket.getInetAddress();
  }

  @Override
  public InetAddress getLocalAddress() {
    return socket.getLocalAddress();
  }

  @Override
  public int getPort() {
    return socket.getPort();
  }

  @Override
  public int getLocalPort() {
    return socket.getLocalPort();
  }

  @Override
  public SocketAddress getRemoteSocketAddress() {
    return socket.getRemoteSocketAddress();
  }

  @Override
  public SocketAddress getLocalSocketAddress() {
    return socket.getLocalSocketAddress();
  }

  @Override
  public SocketChannel getChannel() {
    return socket.getChannel();
  }

  @Override
  public InputStream getInputStream() throws IOException {
    return socket.getInputStream();
  }

  @Override
  public OutputStream getOutputStream() throws IOException {
    return socket.getOutputStream();
  }

  @Override
  public boolean getTcpNoDelay() throws SocketException {
    return socket.getTcpNoDelay();
  }

  @Override
  public void setTcpNoDelay(boolean on) throws SocketException {
    socket.setTcpNoDelay(on);
  }

  @Override
  public void setSoLinger(boolean on, int linger) throws SocketException {
    socket.setSoLinger(on, linger);
  }

  @Override
  public int getSoLinger() throws SocketException {
    return socket.getSoLinger();
  }

  @Override
  public void sendUrgentData(int data) throws IOException {
    socket.sendUrgentData(data);
  }

  @Override
  public boolean getOOBInline() throws SocketException {
    return socket.getOOBInline();
  }

  @Override
  public void setOOBInline(boolean on) throws SocketException {
    socket.setOOBInline(on);
  }

  @Override
  public int getSoTimeout() throws SocketException {
    return socket.getSoTimeout();
  }

  @Override
  public void setSoTimeout(int timeout) throws SocketException {
    socket.setSoTimeout(timeout);
  }

  @Override
  public int getSendBufferSize() throws SocketException {
    return socket.getSendBufferSize();
  }

  @Override
  public void setSendBufferSize(int size) throws SocketException {
    socket.setSendBufferSize(size);
  }

  @Override
  public int getReceiveBufferSize() throws SocketException {
    return socket.getReceiveBufferSize();
  }

  @Override
  public void setReceiveBufferSize(int size) throws SocketException {
    socket.setReceiveBufferSize(size);
  }

  @Override
  public boolean getKeepAlive() throws SocketException {
    return socket.getKeepAlive();
  }

  @Override
  public void setKeepAlive(boolean on) throws SocketException {
    socket.setKeepAlive(on);
  }

  @Override
  public int getTrafficClass() throws SocketException {
    return socket.getTrafficClass();
  }

  @Override
  public void setTrafficClass(int tc) throws SocketException {
    socket.setTrafficClass(tc);
  }

  @Override
  public boolean getReuseAddress() throws SocketException {
    return socket.getReuseAddress();
  }

  @Override
  public void setReuseAddress(boolean on) throws SocketException {
    socket.setReuseAddress(on);
  }

  @Override
  public void close() throws IOException {
    socket.close();
  }

  @Override
  public void shutdownInput() throws IOException {
    socket.shutdownInput();
  }

  @Override
  public void shutdownOutput() throws IOException {
    socket.shutdownOutput();
  }

  @Override
  public String toString() {
    return socket.toString();
  }

  @Override
  public boolean isConnected() {
    return socket.isConnected();
  }

  @Override
  public boolean isBound() {
    return socket.isBound();
  }

  @Override
  public boolean isClosed() {
    return socket.isClosed();
  }

  @Override
  public boolean isInputShutdown() {
    return socket.isInputShutdown();
  }

  @Override
  public boolean isOutputShutdown() {
    return socket.isOutputShutdown();
  }

  @Override
  public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
    socket.setPerformancePreferences(connectionTime, latency, bandwidth);
  }
}
