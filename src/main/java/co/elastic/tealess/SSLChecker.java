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
import co.elastic.Resolver;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.X509Certificate;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.FINISHED;

public class SSLChecker {
  /* Diagnose SSL problems
   * 1) TCP connect
   * 2) TLS/SSL protocol negotiation
   * 3) (low priority) TLS/SSL cipher negotiation
   * 4) Certificate trust problems
   * 5) Hostname verification (RFC6125?)
   */

  private static final long defaultTimeout = 1000;
  private final Resolver resolver = Resolver.SystemResolver;
  private final Logger logger = LogManager.getLogger();
  private KeyStore trustStore;
  private KeyStore keyStore;
  private SSLContext ctx;

  private PeerCertificateDetails peerCertificateDetails;

  public SSLChecker(SSLContextBuilder cb) throws KeyManagementException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
    cb.setTracker(this::setPeerCertificateDetails);
    ctx = cb.build();
  }

  public SSLChecker(KeyStore keyStore, KeyStore trustStore) throws KeyManagementException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
    this.trustStore = trustStore;
    this.keyStore = keyStore;

    SSLContextBuilder ctxbuilder = new SSLContextBuilder();
    ctxbuilder.setTrustStore(trustStore);
    ctxbuilder.setKeyStore(keyStore);
    ctxbuilder.setTracker(this::setPeerCertificateDetails);

    ctx = ctxbuilder.build();
  }

  private void setPeerCertificateDetails(X509Certificate[] chain, String authType, Throwable exception) {
    peerCertificateDetails = new PeerCertificateDetails(chain, authType, exception);
  }

  public void check(String hostname, int port) throws IOException {
    for (InetAddress address : this.resolver.resolve(hostname)) {
      check(new InetSocketAddress(address, port), hostname);
    }
  }

  public SSLReport check(InetSocketAddress address, String name) {
    return check(address, name, defaultTimeout);
  }

  public SSLReport check(InetSocketAddress address, String name, long timeout) {
    SSLReport sslReport = new SSLReport();
    sslReport.setSSLContext(ctx);
    sslReport.setHostname(name);
    sslReport.setAddress(address);

    logger.debug("Trying {} (expected hostname {})", address, name);
    SocketChannel socket;
    try {
      socket = SocketChannel.open();
      socket.configureBlocking(false);
    } catch (IOException e) {
      sslReport.setFailed(e);
      return sslReport;
    }


    checkConnect(sslReport, socket, timeout);
    if (sslReport.getException() != null) {
      return sslReport;
    }

    checkHandshake(sslReport, socket);
    return sslReport;
  }

  private void checkConnect(SSLReport sslReport, SocketChannel socket, long timeout) {
    final InetSocketAddress address = sslReport.getAddress();
    try {
      logger.trace("Connecting to {}", address);
      Selector selector = Selector.open();
      SelectionKey sk = socket.register(selector, SelectionKey.OP_CONNECT);
      socket.connect(address);
      selector.select(timeout);
      //System.out.println("connectable:" + sk.isConnectable());
      if (!sk.isConnectable()) {
        sslReport.setFailed(new SocketTimeoutException());
        return;
      }
      if (socket.isConnectionPending()) {
        socket.finishConnect();
      }
    } catch (ConnectException e) {
      logger.debug("Connection failed to {}: {}", address, e);
      sslReport.setFailed(e);
      return;
    } catch (IOException e) {
      logger.error("Failed connecting to {}: {}", address, e);
      sslReport.setFailed(e);
      return;
    }

    logger.debug("Connection successful to {}", address);
  }

  private void checkHandshake(SSLReport sslReport, SocketChannel socket) {
    final InetSocketAddress address = sslReport.getAddress();
    final String name = sslReport.getHostname();
    SSLEngine sslEngine = ctx.createSSLEngine(name, address.getPort());
    sslEngine.setUseClientMode(true);

    try {
      sslEngine.beginHandshake();
    } catch (SSLException e) {
      sslReport.setFailed(e);
      Throwable cause = Blame.get(e);
      logger.warn("beginHandshake failed: [{}] {}", cause.getClass(), cause.getMessage());
    }

    // TODO: Is this enough bytes?
    int size = sslEngine.getSession().getApplicationBufferSize() * 2;
    ByteBuffer localText = ByteBuffer.allocate(size);
    ByteBuffer localWire = ByteBuffer.allocate(size);
    ByteBuffer peerText = ByteBuffer.allocate(size);
    ByteBuffer peerWire = ByteBuffer.allocate(size);
    localText.put("SSL TEST. HELLO.".getBytes());
    localText.flip();

    SSLEngineResult result = null;
    try {
      SSLEngineResult.HandshakeStatus state;
      state = sslEngine.getHandshakeStatus();
      while (state != FINISHED) {
        switch (state) {
          case NEED_TASK:
            sslEngine.getDelegatedTask().run();
            state = sslEngine.getHandshakeStatus();
            break;
          case NEED_WRAP:
            localWire.clear();
            result = sslEngine.wrap(localText, localWire);
            state = result.getHandshakeStatus();
            localWire.flip();
            while (localWire.hasRemaining()) socket.write(localWire);
            localWire.compact();
            break;
          case NEED_UNWRAP:
            socket.read(peerWire);
            peerWire.flip();
            result = sslEngine.unwrap(peerWire, peerText);
            state = result.getHandshakeStatus();
            peerWire.compact();
            break;
        }
      }
    } catch (IOException e) {
      Throwable cause = Blame.get(e);
      sslReport.setFailed(e);
      sslReport.setSSLSession(sslEngine.getHandshakeSession());
      sslReport.setPeerCertificateDetails(peerCertificateDetails);
      logger.warn("beginHandshake failed", e);
    }
  }
}
