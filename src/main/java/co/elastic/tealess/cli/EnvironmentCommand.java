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
import co.elastic.tealess.ConfigurationProblem;
import co.elastic.tealess.cli.environment.CipherSuite;
import co.elastic.tealess.cli.environment.Protocol;
import co.elastic.tealess.cli.input.ParserResult;
import io.netty.handler.ssl.OpenSsl;
import io.netty.util.Version;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Created by jls on 1/20/17.
 */
public class EnvironmentCommand implements Command {
  private static final Logger logger = LogManager.getLogger();

  public static Set<Protocol> getProtocols(SSLEngine engine) {
    Set<Protocol> protocols = new TreeSet<>();
    Arrays.stream(engine.getSupportedProtocols()).forEach(name -> {
      boolean enabled = Arrays.stream(engine.getEnabledProtocols()).anyMatch(p -> p.equals(name));
      protocols.add(new Protocol(name, enabled));
    });
    return protocols;
  }

  public static Set<CipherSuite> getCipherSuites(SSLEngine engine) {
    Set<CipherSuite> suites = new TreeSet<>();

    List<String> javaAllCiphers = Arrays.asList(engine.getSupportedCipherSuites());
    List<String> javaEnabledCiphers = Arrays.asList(engine.getEnabledCipherSuites());
    List<String> tcnativeCiphers = new ArrayList<>(OpenSsl.availableJavaCipherSuites());

    Set<String> ciphers = new TreeSet<>();
    ciphers.addAll(javaAllCiphers);
    ciphers.addAll(tcnativeCiphers);

    ciphers.stream().sorted().forEach(suite -> {
      boolean enabled = javaEnabledCiphers.contains(suite);
      boolean java = javaAllCiphers.contains(suite);
      boolean tcnative = tcnativeCiphers.contains(suite);
      suites.add(new CipherSuite(suite, enabled, java, tcnative));
    });
    return suites;
  }

  public ParserResult parse(String[] args) {
    // Nothing to do. No flags.
    return ParserResult.success();
  }

  public static SSLEngine getSSLEngine() throws Bug {
    SSLContext ctx;
    try {
      ctx = SSLContext.getDefault();
    } catch (NoSuchAlgorithmException e) {
      throw new Bug("Could not get default SSL Context. Something went wrong.", e);
    }
    return ctx.createSSLEngine();
  }

  public void run() throws ConfigurationProblem, Bug {
    System.out.printf("Java %s %s\n", System.getProperty("java.runtime.name"), System.getProperty("java.version"));

    SSLEngine engine = getSSLEngine();

    showNettyDetails();

    System.out.println();

    System.out.println("Supported protocols: ('+' means enabled by default) ");
    getProtocols(engine).stream().sorted().forEach(System.out::println);

    System.out.println("Supported cipher suites: ('+' means enabled by default) ");
    getCipherSuites(engine).stream().sorted().forEach(System.out::println);
  }

  private void showNettyDetails() {
    if (OpenSsl.isAvailable()) {
      System.out.printf("Netty OpenSSL support is available.\n");
    } else {
      Throwable e = OpenSsl.unavailabilityCause();
      System.out.printf("Netty's OpenSSL layer could not be loaded: %s\n", e.getMessage());
    }

    System.out.println("Netty details:");
    Map<String, Version> nettyComponents = Version.identify();
    Version.identify().forEach((k, v) -> {
      if (k.contains("tcnative")) {
        System.out.printf("  %s\n", v);
      }
    });


  }
}
