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
  private static final String ORACLE_JVM_RUNTIME_NAME = "Java(TM) SE Runtime Environment";

  private static final String trustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
  private static final Logger logger = LogManager.getLogger();

  private static final SSLCertificateVerificationTracker defaultTracker = (chain, authType, exception) -> System.out.println("Server certificate chain: " + chain);
  private static final SSLParameters defaultParameters;
  private static final SSLParameters supportedParameters;

  static {
    final SSLContext defaultContext;
    try {
      defaultContext = SSLContext.getDefault();
    } catch (NoSuchAlgorithmException e) {
      // A java.lang.Error feels appropriate for this kind of catastrophic failure.
      throw new Error("SSLContext.getDefault() failed. This means something is very wrong, and unexpected, with the JVM or its configuration.", e);
    }

    defaultParameters = defaultContext.getDefaultSSLParameters();
    supportedParameters = defaultContext.getSupportedSSLParameters();
  }

  // XXX: I don't see a strong reason for someone to want to provide their own. Maybe during testing?
  private final SecureRandom random = new SecureRandom();
  private SSLCertificateVerificationTracker tracker = defaultTracker;
  private String[] cipherSuites = defaultParameters.getCipherSuites();
  private String[] protocols = defaultParameters.getProtocols();

  private KeyStore trustStore;
  private KeyManagerFactory keyManagerFactory;

  // XXX: Do we need this method to be public?
  public void setTracker(SSLCertificateVerificationTracker tracker) {
    if (tracker == null) {
      throw new IllegalArgumentException("tracker cannot be null");
    }
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

    if (keyManagerFactory != null) {
      kms = Arrays.stream(keyManagerFactory.getKeyManagers())
        .map((km) -> new LoggingKeyManager((X509KeyManager) km))
        .toArray(X509KeyManager[]::new);
    }

    TrustManager[] tms = buildTrustStore();

    logger.trace("Building SSLContext with keys:{}, trusts:{}", kms, tms);

    SSLContextSpi spi = new TealessSSLContextSpi(ctx, cipherSuites);
    SSLContext tealessContext = new TealessSSLContext(spi, null, null);
    tealessContext.init(kms, tms, random);
    return tealessContext;
  }

  private TrustManager[] buildTrustStore() throws NoSuchAlgorithmException, KeyStoreException {
    final TrustManagerFactory tmf = TrustManagerFactory.getInstance(trustManagerAlgorithm);

    if (trustStore != null) {
      logger.trace("Using custom trust store with " + trustStore.size() + " entries");
      tmf.init(trustStore);
    } else {
      logger.trace("Using system default trust store");
      tmf.init((KeyStore) null);
    }

    // Wrap java's TrustManagers in our own so that we can track verification failures.
    //return Arrays.stream(tmf.getTrustManagers())
            //.map((tm) -> new TrackingTrustManager((X509TrustManager) tm, tracker))
            //.toArray(TrustManager[]::new);
    return tmf.getTrustManagers();
  }

  public void setKeyManagerFactory(KeyManagerFactory keyManagerFactory) {
    this.keyManagerFactory = keyManagerFactory;
  }

  public void setCipherSuites(String[] cipherSuites) throws IllegalArgumentException {
    for (String cipherSuite : cipherSuites) {
      if (!isValidCipherSuite(cipherSuite)) {
        // XXX: do special handling if this cipher suite is known to be enabled by Oracle's JCE Unlimited Strength Encryption
        // ^^^ It'd be nice to notify the user of the obvious remediation if we know this is unsupported because of Oracle's JCE USC.
        // If the ciphersuite is known but probably disabled because the user is using Oracle JRE without JCE Unlimited Strength installed
        try {
          SSLContext c = SSLContext.getDefault();
          SSLEngine sslEngine = c.createSSLEngine();
          sslEngine.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_AES_256_CBC_SHA256"});
        } catch (IllegalArgumentException e) {
          // Wrap the IllegalArgumentException message in something that includes more context for the user.
          if (e.getMessage().startsWith("Unsupported ciphersuite " + cipherSuite)) {
            // probably an unknown or invalid cipher suite name.
            throw new IllegalArgumentException(e.getMessage() + ". Supported cipher suites are: " + Arrays.asList(supportedParameters.getCipherSuites()));
          } else if (e.getMessage().equals("Cannot support " + cipherSuite + " with currently installed providers")) {
            // This likely means the user is asking for a cipher that is disabled by some Java configuration.
            // In my testing, I found this occurred when using Oracle Java *without* the Unlimited Strength Cryptography policy installed.
            // For example, the cipher suite "TLS_RSA_WITH_AES_256_CBC_SHA256" will fail with the above error if the JCE USC is not installed.
            // This only impacts Oracle JVM, not OpenJDK.
            // This check should only be needed for older Java 8 releases since Unlimited Strength is now default: https://bugs.openjdk.java.net/browse/JDK-8170157
            if (System.getProperty("java.runtime.name").equals(ORACLE_JVM_RUNTIME_NAME)) {
              throw new IllegalArgumentException(e.getMessage() + ". This probably means you need to install the Oracle Java Cryptography Extension Unlimited Strength Cryptographic Policy. Supported cipher suites are: " + Arrays.asList(supportedParameters.getCipherSuites()));
            } else {
              throw new IllegalArgumentException(e.getMessage() + ". Supported cipher suites are: " + Arrays.asList(supportedParameters.getCipherSuites()));
            }
          }
        } catch (NoSuchAlgorithmException e) {
          e.printStackTrace();
        }

        throw new IllegalArgumentException("The cipher suite '" + cipherSuite + "' is not supported. Supported cipher suites are: " + Arrays.asList(supportedParameters.getCipherSuites()));
      }
    }
    this.cipherSuites = cipherSuites;
  }

  private boolean isValidCipherSuite(String cipherSuite) {
    for (String suite : supportedParameters.getCipherSuites()) {
      if (cipherSuite.equals(suite)) {
        return true;
      }
    }
    return false;
  }

  public void setProtocols(String[] protocols) {
    for (String protocol : protocols) {
      if (!isValidProtocol(protocol)) {
        throw new IllegalArgumentException("The protocol '" + protocol + "' is not supported. Supported protocols are: " + Arrays.asList(supportedParameters.getCipherSuites()));
      }
    }

    this.protocols = protocols;
  }

  private boolean isValidProtocol(String protocol) {
    for (String supportedProtocol: supportedParameters.getProtocols()) {
      if (protocol.equals(supportedProtocol)) {
        return true;
      }
    }
    return false;
  }

  public interface SSLCertificateVerificationTracker {
    void track(X509Certificate[] chain, String authType, Throwable exception);
  }
} // SSLContextBuilder
