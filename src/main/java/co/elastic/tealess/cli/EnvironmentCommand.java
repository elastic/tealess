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
import co.elastic.tealess.cli.input.ParserResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Created by jls on 1/20/17.
 */
public class EnvironmentCommand implements Command {
  private static final String PACKAGE_LOGGER_NAME = "co.elastic";
  private static final Logger logger = LogManager.getLogger();

  public ParserResult parse(String[] args) throws ConfigurationProblem {
    // Nothing to do. No flags.
    return ParserResult.success();
  }

  public void run() throws ConfigurationProblem, Bug {
    System.out.printf("Java %s %s\n", System.getProperty("java.runtime.name"), System.getProperty("java.version"));
    SSLContext ctx = null;
    try {
      ctx = SSLContext.getDefault();
    } catch (NoSuchAlgorithmException e) {
      throw new Bug("Could not get default SSL Context. Something went wrong.", e);
    }
    SSLEngine engine = ctx.createSSLEngine();

    System.out.println("Supported protocols: ('+' means enabled by default) ");
    Arrays.stream(engine.getSupportedProtocols()).sorted().forEach(suite -> {
      boolean enabled = Arrays.stream(engine.getEnabledProtocols()).anyMatch(s -> s.equals(suite));
      System.out.printf("%s %s\n", enabled ? "+" : " ", suite);
    });

    System.out.println("Supported cipher suites: ('+' means enabled by default) ");
    Arrays.stream(engine.getSupportedCipherSuites()).sorted().forEach(suite -> {
      boolean enabled = Arrays.stream(engine.getEnabledCipherSuites()).anyMatch(s -> s.equals(suite));
      System.out.printf("%s %s\n", enabled ? "+" : " ", suite);
    });
  }
}
