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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class SSLChecker {
  /* Diagnose SSL problems
   * 1) TCP connect
   * 2) TLS/SSL protocol negotiation
   * 3) (low priority) TLS/SSL cipher negotiation
   * 4) Certificate trust problems
   * 5) Hostname verification (RFC6125?)
   */

  private static final int defaultTimeout = 1000;
  private static final Logger logger = LogManager.getLogger();
  private SSLContext ctx;
  private PeerCertificateDetails peerCertificateDetails;

  public SSLChecker(SSLContextBuilder cb) throws KeyManagementException, KeyStoreException, NoSuchAlgorithmException {
    cb.setTracker(this::setPeerCertificateDetails);
    ctx = cb.build();
  }

  private static Collection<InetAddress> getAddresses(InetSocketAddress address) throws ConfigurationProblem {
    final String hostname = address.getHostString();

    final Collection<InetAddress> addresses;
    logger.trace("Doing name resolution on {}", hostname);
    try {
      return Resolver.SystemResolver.resolve(hostname);
    } catch (UnknownHostException e) {
      throw new ConfigurationProblem("Unknown host", e);
    }
  }

  private void setPeerCertificateDetails(X509Certificate[] chain, String authType, Throwable exception) {
    peerCertificateDetails = new PeerCertificateDetails(chain, authType, exception);
  }

  public List<SSLReport> checkAll(InetSocketAddress address) throws ConfigurationProblem {
    final String hostname = address.getHostString();
    final Collection<InetAddress> addresses = getAddresses(address);
    return addresses.stream()
            .map(a -> check(new InetSocketAddress(a, address.getPort()), hostname))
            .collect(Collectors.toList());
  }

  public SSLReport check(InetSocketAddress address, String name) {
    return check(address, name, defaultTimeout);
  }

  private SSLReport check(InetSocketAddress address, String name, int timeout) {
    SSLReport sslReport = new SSLReport();
    sslReport.setSSLContext(ctx);
    sslReport.setHostname(name);
    sslReport.setAddress(address);
    sslReport.setTimeout(timeout);

    logger.debug("Trying address {} (hostname {})", address, name);

    try (Socket socket = new Socket()) {
      checkConnect(sslReport, socket, timeout);
      if (sslReport.getException() != null) {
        return sslReport;
      }

      checkHandshake(sslReport, socket);
      if (sslReport.getException() != null) {
        return sslReport;
      }

      checkHostnameVerification(sslReport);
    } catch (IOException e) {
      System.out.println("Failure on socket: " + e);
    }
    return sslReport;
  }

  private void checkHostnameVerification(SSLReport sslReport) {
    // XXX: Implement
    //HostnameVerifier hv = new DefaultHostnameVerifier();
    //sslReport.setHostnameVerified(hv.verify(sslReport.getHostname(), sslReport.getSSLSession()));
  }

  private void checkConnect(SSLReport sslReport, Socket socket, int timeout) {
    final InetSocketAddress address = sslReport.getAddress();
    try {
      logger.trace("Connecting to {}", address);
      socket.connect(address, timeout);
    } catch (IOException e) {
      logger.error("Failed connecting to {}: {}", address, e);
      sslReport.setFailed(e);
      return;
    }

    logger.debug("Connection successful to {}", address);
  }

  private void checkHandshake(SSLReport sslReport, Socket socket) {
    final InetSocketAddress address = sslReport.getAddress();
    final String name = sslReport.getHostname();
    SSLSocketFactory socketFactory = ctx.getSocketFactory();

    final SSLSocket sslSocket;
    try {
      socket.setSoTimeout(1000);
      sslSocket = (SSLSocket) socketFactory.createSocket(socket, name, sslReport.getAddress().getPort(), true);
      sslSocket.addHandshakeCompletedListener(e -> logger.debug("Handshake completed: {}", e));
    } catch (IOException e) {
      sslReport.setFailed(e);
      Throwable cause = Blame.get(e);
      logger.warn("beginHandshake failed: [{}] {}", cause.getClass(), cause.getMessage());
      return;
    }

    // Calling getSession here will implicitly attempt to complete the TLS handshake
    // if it is not already done.
    try {
      sslSocket.startHandshake();
    } catch (IOException e) {
      sslReport.setFailed(e);
      return;
    }

    sslReport.setSSLSession(sslSocket.getSession());
    sslReport.setPeerCertificateDetails(peerCertificateDetails);
    if (peerCertificateDetails != null && peerCertificateDetails.getException() != null) {
      sslReport.setFailed(peerCertificateDetails.getException());
    }
  }
}
