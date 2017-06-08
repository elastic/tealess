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

import co.elastic.Bug;
import co.elastic.Resolver;
import co.elastic.tealess.*;
import co.elastic.tealess.cli.input.ArgsParser;
import co.elastic.tealess.cli.input.InetSocketAddressInput;
import co.elastic.tealess.cli.input.ParserResult;
import co.elastic.tealess.cli.input.PathInput;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Created by jls on 10/27/16.
 */
public class ConnectCommand implements Command {
  private static final String PACKAGE_LOGGER_NAME = "co.elastic";
  private static final Logger logger = LogManager.getLogger();
  public static final String DESCRIPTION = "Connect to an address with SSL/TLS and diagnose the result.";
  private final KeyStoreBuilder keys;
  private final KeyStoreBuilder trust;

  private final ArgsParser parser = new ArgsParser();

  private final Setting<Path> capath = parser.addNamed(new Setting<>("capath", "The path to a file containing one or more certificates to trust in PEM format.", PathInput.singleton));
  private final Setting<Path> trustStore = parser.addNamed(new Setting<>("truststore", "The path to a java keystore or pkcs12 file containing certificate authorities to trust", PathInput.singleton))
    .setDefaultValue(KeyStoreBuilder.defaultTrustStorePath);
  private final Setting<Path> keyStore = parser.addNamed(new Setting<>("keystore", "The path to a java keystore or pkcs12 file containing private key(s) and client certificates to use when connecting to a remote server.", PathInput.singleton));
  private final Setting<Level> logLevel = parser.addNamed(new Setting<Level>("log-level", "The log level"))
    .setDefaultValue(Level.INFO)
    .parseWith(Level::valueOf);
  private final Setting<InetSocketAddress> address = parser.addPositional(new Setting<>("address", "The address in form of `host` or `host:port` to connect", new InetSocketAddressInput(443)));

  public ConnectCommand() throws Bug {
    try {
      keys = new KeyStoreBuilder();
      trust = new KeyStoreBuilder();
    } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
      throw new Bug("'new KeyStoreBuilder' failed", e);
    }
  }

  public ParserResult parse(String[] args) {
    parser.setDescription(DESCRIPTION);
    Iterator<String> argsi = Arrays.asList(args).iterator();

    ParserResult result = parser.parse(argsi);
    if (!result.getSuccess()) {
      if (result.getDetails() != null) {
        System.out.println(result.getDetails());
        System.out.println();
      }
      parser.showHelp("tealess");
      return result;
    }

    if (capath.getValue() != null) {
      try {
        logger.info("Adding to trust: capath {}", capath.getValue());
        trust.addCAPath(capath.getValue());
      } catch (CertificateException | IOException | KeyStoreException e) {
        return ParserResult.error("Failed adding certificate authorities from path " + capath.getValue(), e);
      }
    }

    if (trustStore.getValue() != null) {
      try {
        trust.useKeyStore(trustStore.getValue().toFile());
      } catch (IOException | KeyStoreException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException e) {
        return ParserResult.error("Failed trying to use keystore " + trustStore.getValue(), e);
      }
    }

    if (keyStore.getValue() != null) {
      try {
        keys.useKeyStore(keyStore.getValue().toFile());
      } catch (IOException | KeyStoreException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException e) {
        return ParserResult.error("Failed trying to use keystore " + keyStore, e);
      }
    } else {
      try {
        keys.empty();
      } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException | UnrecoverableKeyException e) {
        return ParserResult.error("Failed creating empty key store", e);
      }
    }

    if (logLevel.getValue() != null) {
      LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
      ctx.getConfiguration().getLoggerConfig(PACKAGE_LOGGER_NAME).setLevel(logLevel.getValue());
      ctx.updateLoggers();
    }
    return result;
  }

  public void run() throws ConfigurationProblem, Bug {
    SSLContextBuilder cb = new SSLContextBuilder();
    try {
      cb.setTrustStore(trust.buildKeyStore());
      cb.setKeyManagerFactory(keys.buildKeyManagerFactory());
    } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
      throw new Bug("Failed building keystores", e);
    }

    SSLChecker checker;
    try {
      checker = new SSLChecker(cb);
    } catch (KeyManagementException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
      throw new ConfigurationProblem("Failed to build tealess context.", e);
    }

    String hostname = address.getValue().getHostString();

    Collection<InetAddress> addresses;
    try {
      logger.trace("Doing name resolution on {}", hostname);
      addresses = Resolver.SystemResolver.resolve(hostname);
    } catch (UnknownHostException e) {
      throw new ConfigurationProblem("Unknown host", e);
    }

    System.out.printf("%s resolved to %d addresses\n", hostname, addresses.size());
    List<SSLReport> reports = addresses.stream()
      .map(a -> checker.check(new InetSocketAddress(a, address.getValue().getPort()), hostname))
      .collect(Collectors.toList());

    System.out.println();

    SSLReportAnalyzer.analyzeMany(reports);
  }

  static char[] promptSecret(String text) {
    System.out.printf("%s: ", text);
    return System.console().readPassword();
  }
}
