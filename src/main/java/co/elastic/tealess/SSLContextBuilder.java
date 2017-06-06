/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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
  private KeyManagerFactory keyManagerFactory;

  public void setTracker(SSLCertificateVerificationTracker tracker) {
    this.tracker = tracker;
  }

  public void setTrustStore(KeyStore trustStore) {
    this.trustStore = trustStore;
  }

  public KeyStore getTrustStore() {
    return this.trustStore;
  }

  public SSLContext build() throws KeyManagementException, KeyStoreException, NoSuchAlgorithmException {
    SSLContext ctx = SSLContext.getInstance("TLS");
    KeyManager[] kms = null;
    TrustManager[] tms = null;

    if (keyManagerFactory != null) {
      kms = Arrays.stream(keyManagerFactory.getKeyManagers())
              .map((km) -> new LoggingKeyManager((X509KeyManager) km))
              .toArray(X509KeyManager[]::new);
    }

    if (trustStore != null) {
      System.out.println("Using custom trust store with " + trustStore.size());
      TrustManagerFactory tmf;
      tmf = TrustManagerFactory.getInstance(trustManagerAlgorithm);
      tmf.init(trustStore);
      // Wrap java's TrustManagers in our own so that we can track verification failures.
      tms = Arrays.stream(tmf.getTrustManagers())
              .map((tm) -> new TrackingTrustManager((X509TrustManager) tm))
              .map((tm) -> {
                tm.setTracker(tracker);
                return tm;
              })
              .toArray(TrustManager[]::new);
    }

    logger.trace("Building SSLContext with keys:{}, trusts:{}", kms, tms);

    ctx.init(kms, tms, random);
    return ctx;
  }

  public void setKeyManagerFactory(KeyManagerFactory keyManagerFactory) {
    this.keyManagerFactory = keyManagerFactory;
  }

  public interface SSLCertificateVerificationTracker {
    void track(X509Certificate[] chain, String authType, Throwable exception);
  }
} // SSLContextBuilder
