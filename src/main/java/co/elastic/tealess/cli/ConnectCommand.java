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

import co.elastic.Blame;
import co.elastic.Bug;
import co.elastic.Resolver;
import co.elastic.tealess.*;
import co.elastic.tealess.cli.input.ArgsParser;
import co.elastic.tealess.cli.input.PathInput;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by jls on 10/27/16.
 */
public class ConnectCommand {
  private static final String PACKAGE_LOGGER_NAME = "co.elastic";
  private static final Logger logger = LogManager.getLogger();
  private final KeyStoreBuilder keys;
  private final KeyStoreBuilder trust;

  private final Setting<Path> capath = new Setting<Path>("capath", "The path to a file containing one or more certificates to trust in PEM format.", PathInput.singleton);
  private final Setting<Path> trustStore = new Setting<Path>("truststore", "The path to a java keystore or pkcs12 file containing certificate authorities to trust", PathInput.singleton)
          .setDefaultValue(KeyStoreBuilder.defaultTrustStorePath);
  private final Setting<Path> keyStore = new Setting<Path>("keystore", "The path to a java keystore or pkcs12 file containing private key(s) and client certificates to use when connecting to a remote server.", PathInput.singleton);
  private final Setting<Level> logLevel = new Setting<Level>("log-level", "The log level")
          .setDefaultValue(Level.INFO)
          .parseWith(value -> Level.valueOf(value));

  private String hostname;
  private int port;

  public ConnectCommand() throws Bug, ConfigurationProblem {
    try {
      keys = new KeyStoreBuilder();
      trust = new KeyStoreBuilder();
    } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
      throw new Bug("'new KeyStoreBuilder' failed", e);
    }
  }


  public void parse(String[] args) throws ConfigurationProblem {
    Iterator<String> argsi = Arrays.asList(args).iterator();

    List<String> remainder = ArgsParser.parseFlags(getSettings(), argsi);

    if (remainder.size() == 1 && remainder.get(0).equals("--help")) {
      ArgsParser.showHelp(this);
      return;
    }

    if (remainder.size() == 0) {
      throw new ConfigurationProblem("Usage: tealess [flags] <address> [port]");
    }

    hostname = remainder.get(0);
    if (remainder.size() == 2) {
      port = Integer.parseInt(remainder.get(1));
    } else {
      port = 443;
    }

    if (capath.getValue() != null) {
      try {
        trust.addCAPath(capath.getValue());
      } catch (CertificateException | FileNotFoundException | KeyStoreException e) {
        throw new ConfigurationProblem("Failed adding certificate authorities from path " + capath.getValue(), e);
      }
    }

    if (trustStore.getValue() != null) {
      try {
        trust.useKeyStore(trustStore.getValue().toFile());
      } catch (IOException | KeyStoreException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException e) {
        throw new ConfigurationProblem("Failed trying to use keystore " + trustStore.getValue(), e);
      }
    }

    if (keyStore.getValue() != null) {
      try {
        keys.useKeyStore(keyStore.getValue().toFile());
      } catch (IOException | KeyStoreException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException e) {
        throw new ConfigurationProblem("Failed trying to use keystore " + keyStore, e);
      }
    }

    if (logLevel.getValue() != null) {
      LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
      ctx.getConfiguration().getLoggerConfig(PACKAGE_LOGGER_NAME).setLevel(logLevel.getValue());
      ctx.updateLoggers();
    }
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

    Collection<InetAddress> addresses;

    try {
      logger.trace("Doing name resolution on {}", hostname);
      addresses = Resolver.SystemResolver.resolve(hostname);
    } catch (UnknownHostException e) {
      throw new ConfigurationProblem("Unknown host", e);
    }

    System.out.printf("%s resolved to %d addresses\n", hostname, addresses.size());
    List<SSLReport> reports = addresses.stream()
            .map(address -> checker.check(new InetSocketAddress(address, port), hostname))
            .collect(Collectors.toList());

    List<SSLReport> successful = reports.stream().filter(SSLReport::success).collect(Collectors.toList());

    if (successful.size() > 0) {
      successful.forEach(r -> System.out.printf("SUCCESS %s\n", r.getAddress()));
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

      SSLReportAnalyzer.analyze(blame, failures.get(0));
    }
  }

  static char[] promptSecret(String text) {
    System.out.printf("%s: ", text);
    return System.console().readPassword();
  }

  private List<Setting<?>> getSettings() throws ConfigurationProblem {
    List<Setting<?>> settings = new LinkedList<>();

    try {
      Field[] fields = this.getClass().getDeclaredFields();
      for (Field field : fields) {
        if (Setting.class.isAssignableFrom(field.getType())) {
          settings.add((Setting<?>) field.get(this));
        }
      }
    } catch (IllegalAccessException e) {
      throw new ConfigurationProblem("Failed to parse flags because the security manager prevented us from using reflection to look for fields of type Setting");
    }

    return settings;
  }
}
