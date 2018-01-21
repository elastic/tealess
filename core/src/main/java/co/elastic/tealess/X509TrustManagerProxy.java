package co.elastic.tealess;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class X509TrustManagerProxy implements X509TrustManager {
  private final X509TrustManager trustManager;

  public X509TrustManagerProxy(X509TrustManager trustManager) {
    this.trustManager = trustManager;
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
