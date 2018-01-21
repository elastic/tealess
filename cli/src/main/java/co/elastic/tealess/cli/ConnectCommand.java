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

package co.elastic.tealess.cli;

import co.elastic.tealess.*;
import co.elastic.tealess.cli.input.ArgsParser;
import co.elastic.tealess.cli.input.InetSocketAddressInput;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Created by jls on 10/27/16.
 */
public class ConnectCommand implements Command {
  private static final Logger logger = LogManager.getLogger();

  private static final String DESCRIPTION = "Connect to an address with SSL/TLS and diagnose the result.";
  private final KeyStoreBuilder keys;
  private final KeyStoreBuilder trust;
  private InetSocketAddress address = null;

  ConnectCommand() throws Bug {
    try {
      keys = new KeyStoreBuilder();
      trust = new KeyStoreBuilder();
    } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
      throw new Bug("'new KeyStoreBuilder' failed", e);
    }
  }

  static char[] promptSecret(String text) {
    System.out.printf("%s: ", text);
    return System.console().readPassword();
  }

  private void setAddress(InetSocketAddress address) {
    this.address = address;
  }

  private void setCAPath(Path path) throws CertificateException, KeyStoreException, IOException {
    logger.info("Adding to trust: capath {}", path);
    trust.addCAPath(path);
  }

  private void setTrustStore(Path path) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    trust.useKeyStore(path.toFile());
  }

  private void setKeyStore(Path path) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    keys.useKeyStore(path.toFile());
  }

  @Override
  public ArgsParser getParser() {
    return new ArgsParser()
            .setDescription(DESCRIPTION)
            .addNamed(new Setting<Level>("log-level", "The log level").setDefaultValue(Level.WARN).parseWith(Level::valueOf), LogUtils::setLogLevel)
            .addNamed(new Setting<Path>("capath", "The path to a file containing one or more certificates to trust in PEM format.").parseWith(Paths::get), this::setCAPath)
            .addNamed(new Setting<Path>("truststore", "The path to a java keystore or pkcs12 file containing certificate authorities to trust").parseWith(Paths::get), this::setTrustStore)
            .addNamed(new Setting<Path>("keystore", "The path to a java keystore or pkcs12 file containing private key(s) and client certificates to use when connecting to a remote server.").parseWith(Paths::get), this::setKeyStore)
            .addPositional(new Setting<>("address", "The address in form of `host` or `host:port` to connect", new InetSocketAddressInput(443)), this::setAddress);
  }

  @Override
  public void run() throws ConfigurationProblem, Bug {
    TealessSSLContextBuilder cb = new TealessSSLContextBuilder();
    try {
      cb.setTrustStore(trust.buildKeyStore());
      cb.setKeyManagerFactory(keys.buildKeyManagerFactory());
    } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
      throw new Bug("Failed building keystores", e);
    }

    SSLChecker checker;
    try {
      checker = new SSLChecker(cb);
    } catch (KeyManagementException | KeyStoreException | NoSuchAlgorithmException e) {
      throw new ConfigurationProblem("Failed to build tealess context.", e);
    }

    String hostname = address.getHostString();

    Collection<InetAddress> addresses;
    try {
      logger.trace("Doing name resolution on {}", hostname);
      addresses = Resolver.SystemResolver.resolve(hostname);
    } catch (UnknownHostException e) {
      throw new ConfigurationProblem("Unknown host", e);
    }

    System.out.printf("%s resolved to %d addresses\n", hostname, addresses.size());
    List<SSLReport> reports = addresses.stream()
            .map(a -> checker.check(new InetSocketAddress(a, address.getPort()), hostname))
            .collect(Collectors.toList());

    System.out.println();

    SSLReportAnalyzer.analyzeMany(reports);
  }
}
