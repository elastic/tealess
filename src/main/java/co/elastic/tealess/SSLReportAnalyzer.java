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

import co.elastic.Blame;
import co.elastic.tealess.tls.*;

import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class SSLReportAnalyzer {

  public static void analyzeMany(List<SSLReport> reports) {
    List<SSLReport> successful = reports.stream().filter(SSLReport::success).collect(Collectors.toList());

    if (successful.size() > 0) {
      successful.forEach(r -> System.out.printf("Success: %s\n", r.getAddress()));
    } else {
      System.out.println("All SSL/TLS connections failed.");
    }

    Map<Class<? extends Throwable>, List<SSLReport>> failureGroups = reports.stream().filter(r -> !r.success()).collect(Collectors.groupingBy(r -> Blame.get(r.getException()).getClass()));
    for (Map.Entry<Class<? extends Throwable>, List<SSLReport>> entry : failureGroups.entrySet()) {
      Class<? extends Throwable> blame = entry.getKey();
      List<SSLReport> failures = entry.getValue();
      System.out.println();
      System.out.printf("Failure: %s\n", blame);
      for (SSLReport r : failures) {
        System.out.printf("  %s\n", r.getAddress());
      }

      analyze(blame, failures.get(0));
      failures.get(0).getException().printStackTrace();
    }
  }

  /* TODO: Use org.apache.logging.log4j.message.ParameterizedMessage to format the report. */

  public static void analyze(Class<? extends Throwable> blame, SSLReport report) {
    // I use Class.getCanonicalName() here to avoid a compiler warning that sun.security internal API.
    if (blame.getCanonicalName().equals("sun.security.provider.certpath.SunCertPathBuilderException")
            || blame == java.security.cert.CertPathValidatorException.class) {
      analyzeCertificatePathProblem(report);
    } else if (blame == java.io.EOFException.class) {
      analyzeEarlyEOF(report);
    } else if (blame == java.net.SocketTimeoutException.class) {
      analyzeTimeout(report);
    } else if (blame == javax.net.ssl.SSLHandshakeException.class) {
      analyzeHandshakeProblem(report);
    } else if (blame == javax.net.ssl.SSLException.class && report.getException().getMessage().matches("Received fatal alert: handshake_failure")) {
      analyzeHandshakeRejected(report);
    } else if (blame == java.io.IOException.class) {
      analyzeHandshakeRejected(report);
    } else {
      System.out.println("  Analysis: " + report.getException().getMessage());
    }
  }

  private static void analyzeHandshakeRejected(SSLReport report) {
    System.out.println("  The SSL/TLS handshake attempt was terminated by the remote server.");
    System.out.println("  One possibility is that the server requires the client to provide a certificate for validation, and maybe the client did not provide one.");
    if (report.getIOObserver() == null) {
      System.out.println("  -- No data was transmitted.. this is probably a bug in this tool.");
      return;
    }

    ByteBuffer outputData = report.getIOObserver().getOutputData();
    ByteBuffer inputData = report.getIOObserver().getInputData();
    System.out.println("Sent frames: " + outputData);
    while (true) {
      try {
        TLSPlaintext plaintext = TLSDecoder.decode(outputData);
        switch (plaintext.getContentType()) {
          case Handshake:
            TLSDecoder.decodeHandshake(plaintext.getPayload());
            break;
        }
        System.out.printf("send: %s\n", TLSDecoder.decode(outputData));
      } catch (InvalidValue invalidValue) {
        invalidValue.printStackTrace();
      } catch (BufferUnderflowException e) {
        break;
      }
    }

    while (true) {
      try {
        TLSPlaintext plaintext = TLSDecoder.decode(inputData);
        System.out.printf("recv: %s\n", plaintext);
        switch (plaintext.getContentType()) {
          case Handshake:
            TLSHandshake handshake = TLSDecoder.decodeHandshake(plaintext.getPayload());
            System.out.println(handshake);
            break;
        }
      } catch (InvalidValue invalidValue) {
        invalidValue.printStackTrace();
      } catch (BufferUnderflowException e) {
        break;
      }
    }
  }

  private static void analyzeTimeout(SSLReport report) {
    System.out.printf("  Connection attempt timed-out after %d milliseconds\n", report.getTimeout());
  }

  private static void analyzeHandshakeProblem(SSLReport report) {
    System.out.println("  Analysis: SSL handshake was rejected by the server.");
    System.out.printf("  Error message: %s\n", report.getException().getMessage());
    System.out.println("  * Maybe: Check the server's logs to see if it can tell you why it's rejected our handshake.");
    System.out.println("  * Maybe: Check if the server can accept any of the ciphers listed below.");
    System.out.println("  ");
    SSLParameters parameters = report.getSSLContext().getDefaultSSLParameters();
    System.out.println("  I used the following TLS/SSL settings:");
    System.out.printf("  Protocols: %s\n", String.join(", ", Arrays.asList(parameters.getProtocols())));
    System.out.printf("  Cipher suites: %s\n", String.join(",", Arrays.asList(parameters.getCipherSuites())));
  }

  private static void analyzeEarlyEOF(SSLReport report) {
    System.out.println("  Analysis: This can occur for a few different reasons. ");
    System.out.println("  * Maybe: The server rejected our SSL/TLS version.");
    System.out.println("  * Maybe: The address targeted is not an SSL/TLS server and closed the connection when we said 'Hello'");
    System.out.println("");
    System.out.println("  I used the following TLS/SSL settings:");
    SSLParameters parameters = report.getSSLContext().getDefaultSSLParameters();
    System.out.printf("  My protocols: %s\n", String.join(", ", Arrays.asList(parameters.getProtocols())));
    System.out.println(report.getSSLSession());
  }

  private static void analyzeCertificatePathProblem(SSLReport report) {
    System.out.println("  Analysis: A certificate-related problem occurred.");
    //System.out.println("  The SSL library said this: " + Blame.get(report.getException()));

    PeerCertificateDetails pcd = report.getPeerCertificateDetails();
    X509Certificate[] chain = pcd.getChain();

    // Is it self-signed?
    if (chain[0].getIssuerX500Principal().equals(chain[0].getSubjectX500Principal())) {
      analyzeSelfSignedCertificate(report);
    }

    // Check if the server-provided chain a complete chain.
    // If not, offer something actionable, like showing the first missing issuer.
    X509Certificate tail = chain[chain.length - 1];
    if (!tail.getIssuerX500Principal().equals(tail.getSubjectX500Principal())) {
      System.out.println();
      System.out.println("The last certificate in the chain provided by the server is missing a trust anchor.");
      System.out.println("A trust anchor is what you would normally provide in a certificate authorities file " +
              "that tells the program about SSL certificate authorities that are to be trusted when doing SSL/TLS handshakes.");
      System.out.println();

      int trustCount = 0;
      try {
        trustCount = report.getSSLContextBuilder().getTrustStore().size();
      } catch (KeyStoreException e) {
        System.out.println("An error occurred while trying to read the trust store: " + e);
        e.printStackTrace();
      }
      System.out.printf("Number of certificates in the trust store: %d\n", trustCount);

      System.out.println();
      System.out.println("This is the certificate, provided by the remote server, that is missing a trust anchor:");
      System.out.printf("  %s\n", tail.getSubjectX500Principal());
      System.out.printf("  issued by %s\n", tail.getIssuerX500Principal());

      // Check the default system keystore. Just in case.
      try {
        KeyStoreBuilder ksb = new KeyStoreBuilder();
        ksb.useDefaultTrustStore();
        KeyStore ks = ksb.buildKeyStore();
        for (Enumeration<String> aliases = ks.aliases(); aliases.hasMoreElements(); ) {
          String alias = aliases.nextElement();
          Certificate trusted = ks.getCertificate(alias);
          try {
            tail.verify(trusted.getPublicKey());
            System.out.println();
            System.out.printf("I did some extra digging and found the issuer of this last certificate in your system's default keystore\n");
            System.out.printf("  Path to system keystore: %s\n", KeyStoreBuilder.defaultTrustStorePath);
            System.out.printf("  The system's keystore alias for the issuer is '%s'\n", alias);
          } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            // Nothing
          }
        }
      } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
        e.printStackTrace();
      }
    }

    for (int i = 1; i < chain.length; i++) {
      X509Certificate previous = chain[i - 1];
      X509Certificate cert = chain[i];

      try {
        previous.verify(cert.getPublicKey());
      } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
        System.out.printf("Certificate signature verification failed on certificate %d in the chain provided by the server", i - 1);
        System.out.printf("  Certificate subject: %s\n", previous.getSubjectX500Principal());
        System.out.printf("  Certificate issuer: %s\n", previous.getIssuerX500Principal());
        System.out.printf("  Verification error: %s\n", e);
      }
    }
  }

  private static void analyzeSelfSignedCertificate(SSLReport report) {
    System.out.println("  Certificate is self-signed. This can be OK, but my keystore doesn't have an entry for it, so I am not trusting it.");
  }
}
