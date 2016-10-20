package co.elastic.tealess;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.net.InetSocketAddress;

class SSLReport {
  private Throwable exception;
  private SSLContext sslContext;
  private SSLSession sslSession;
  private InetSocketAddress address;
  private PeerCertificateDetails peerCertificateDetails;
  private String hostname;

  SSLReport() {
    // Nothing
  }

  String getHostname() {
    return hostname;
  }

  void setHostname(String hostname) {
    this.hostname = hostname;
  }

  InetSocketAddress getAddress() {
    return address;
  }

  void setAddress(InetSocketAddress address) {
    this.address = address;
  }

  void setFailed(Throwable e) {
    exception = e;
  }

  SSLContext getSSLContext() {
    return sslContext;
  }

  void setSSLContext(SSLContext ctx) {
    sslContext = ctx;
  }

  SSLSession getSSLSession() {
    return sslSession;
  }

  void setSSLSession(SSLSession s) {
    sslSession = s;
  }

  public PeerCertificateDetails getPeerCertificateDetails() {
    return peerCertificateDetails;
  }

  void setPeerCertificateDetails(PeerCertificateDetails details) {
    peerCertificateDetails = details;
  }

  Throwable getException() {
    return exception;
  }

  boolean success() {
    return exception == null;
  }
}
