package co.elastic.tealess;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class X509ExtendedTrustManagerProxy extends X509ExtendedTrustManager {
  private final X509ExtendedTrustManager trustManager;

  X509ExtendedTrustManagerProxy(X509ExtendedTrustManager trustManager) {
    this.trustManager = trustManager;
  }

  public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
    trustManager.checkClientTrusted(x509Certificates, s, socket);
  }

  public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
    trustManager.checkServerTrusted(x509Certificates, s, socket);
  }

  public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
    trustManager.checkClientTrusted(x509Certificates, s, sslEngine);
  }

  public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
    trustManager.checkServerTrusted(x509Certificates, s, sslEngine);
  }

  public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
    trustManager.checkClientTrusted(x509Certificates, s);
  }

  public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
    trustManager.checkServerTrusted(x509Certificates, s);
  }

  public X509Certificate[] getAcceptedIssuers() {
    return trustManager.getAcceptedIssuers();
  }
}
