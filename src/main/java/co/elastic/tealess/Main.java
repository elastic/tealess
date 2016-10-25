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
import co.elastic.Bug;
import co.elastic.Resolver;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.stream.Collectors;

public class Main {
  private static final String PACKAGE_LOGGER_NAME = "co.elastic";
  private static final Logger logger = LogManager.getLogger();
  private final String[] args;

  private Main(String[] args) {
    this.args = args;
  }

  public static void main(String[] args) throws Exception {
    try {
      (new Main(args)).run();
    } catch (Bug e) {
      System.out.printf("Bug: %s\n", e.getMessage());
      e.printStackTrace(System.out);
    } catch (ConfigurationProblem e) {
      String message;
      if (e.getCause() != null) {
        message = String.format("Configuration error: %s. Reason: %s", e.getMessage(), e.getCause().getMessage());
        System.out.println(e.getCause().getMessage());
        e.getCause().printStackTrace(System.out);
      } else {
        message = String.format("Configuration error: %s.", e.getMessage());
      }
      System.out.println(message);
      System.exit(1);
    }
  }

  private static List<String> parseFlags(KeyStoreBuilder keys, KeyStoreBuilder trust, Iterator<String> i) throws ConfigurationProblem, Bug {
    List<String> parameters = new LinkedList<>();

    flagIteration:
    while (i.hasNext()) {
      String entry = i.next();
      String arg;
      char[] secret;
      switch (entry) {
        case "--capath":
          arg = i.next();
          try {
            trust.addCAPath(arg);
          } catch (CertificateException | FileNotFoundException | KeyStoreException e) {
            throw new ConfigurationProblem("Failed adding certificate authorities from file " + arg, e);
          }
          break;
        case "--truststore":
          arg = i.next();
          try {
            trust.useKeyStore(arg);
          } catch (IOException | KeyStoreException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException e) {
            throw new ConfigurationProblem("Failed trying to use keystore " + arg, e);
          }
          break;
        case "--keystore":
          arg = i.next();
          try {
            keys.useKeyStore(arg);
          } catch (IOException | KeyStoreException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException e) {
            throw new ConfigurationProblem("Failed trying to use keystore " + arg, e);
          }
          break;
        case "--log-level":
          arg = i.next();
          LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
          ctx.getConfiguration().getLoggerConfig(PACKAGE_LOGGER_NAME).setLevel(Level.valueOf(arg));
          ctx.updateLoggers();
          break;
        case "--":
          break flagIteration;
        default:
          if (entry.startsWith("-")) {
            throw new ConfigurationProblem("Invalid flag: " + entry);
          }
          parameters.add(entry); // not a flag, the first non-flag parameter
          break flagIteration;
      }
    }

    while (i.hasNext()) {
      parameters.add(i.next());
    }

    return parameters;
  }

  private void run() throws ConfigurationProblem, Bug {
    SSLContextBuilder cb = new SSLContextBuilder();
    Iterator<String> i = Arrays.asList(args).iterator();

    KeyStoreBuilder keys, trust;
    try {
      keys = new KeyStoreBuilder();
      trust = new KeyStoreBuilder();
    } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
      throw new Bug("Failed to new KeyStoreBuilder failed", e);
    }

    List<String> remainder = parseFlags(keys, trust, i);

    try {
      cb.setTrustStore(trust.buildKeyStore());
      cb.setKeyManagerFactory(keys.buildKeyManagerFactory());
    } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
      throw new Bug("Failed building keystores", e);
    }

    if (remainder.size() == 0) {
      throw new ConfigurationProblem("Usage: tealess [flags] <address> [port]");
    }

    String hostname = remainder.get(0);
    final int port;

    if (remainder.size() == 2) {
      port = Integer.parseInt(remainder.get(1));
    } else {
      port = 443;
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

  private static class SubjectAlternative {
    static final int DNS = 2;
    static final int IPAddress = 7;
  }

  private static class ConfigurationProblem extends Exception {
    ConfigurationProblem(String message) {
      super(message);
    }

    ConfigurationProblem(String message, Throwable cause) {
      super(message, cause);
    }
  }

  static char[] promptSecret(String text) {
    System.out.printf("%s: ", text);
    return System.console().readPassword();
  }
}
