package co.elastic.tealess;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class SSLContextBuilder {
  private final SecureRandom random = new SecureRandom();
  private final String keyManagerAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
  private final String trustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
  private final Logger logger = LogManager.getLogger();
  private KeyStore trustStore;
  private KeyStore keyStore;
  private SSLCertificateVerificationTracker tracker;

  public void setTracker(SSLCertificateVerificationTracker tracker) {
    this.tracker = tracker;
  }

  public void setKeyStore(KeyStore keyStore) {
    this.keyStore = keyStore;
  }

  public void setTrustStore(KeyStore trustStore) {
    this.trustStore = trustStore;
  }

  public SSLContext build() throws KeyManagementException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
    SSLContext ctx = SSLContext.getInstance("TLS");
    KeyManager[] kms = null;
    TrustManager[] tms = null;

    //logger.info("Trusting {} certificates", keystoreTrustedCertificates(keystore).size());
    if (keyStore != null) {
      KeyManagerFactory kmf;
      kmf = KeyManagerFactory.getInstance(keyManagerAlgorithm);
      kmf.init(keyStore, null);
      kms = kmf.getKeyManagers();
    }

    if (trustStore != null) {
      TrustManagerFactory tmf;
      tmf = TrustManagerFactory.getInstance(trustManagerAlgorithm);
      tmf.init(trustStore);
      tms = Arrays.stream(tmf.getTrustManagers())
              .map((tm) -> new TrackingTrustManager((X509TrustManager) tm))
              .map((tm) -> {
                tm.setTracker(tracker);
                return tm;
              })
              .toArray(TrustManager[]::new);
    }

    logger.trace("Building SSLContext with trust: key:{}, trust:{}", kms, tms);

    ctx.init(kms, tms, random);
    return ctx;
  }

  public interface SSLCertificateVerificationTracker {
    void track(X509Certificate[] chain, String authType, Throwable exception);
  }
} // SSLContextBuilder
