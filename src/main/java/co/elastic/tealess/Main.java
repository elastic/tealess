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
import co.elastic.tealess.cli.ConnectCommand;
import co.elastic.tealess.cli.Setting;
import co.elastic.tealess.cli.input.InvalidValue;
import co.elastic.tealess.cli.input.PathInput;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.ConfigurationException;

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

public class Main {
  private static final String PACKAGE_LOGGER_NAME = "co.elastic";
  private static final Logger logger = LogManager.getLogger();

  private String command;
  private String[] args;

  public static void main(String[] args) throws Exception {
    try {
      ConnectCommand command = new ConnectCommand();
      command.parse(args);
      command.run();
      //} catch (Bug e) {
      //System.out.printf("Bug: %s\n", e.getMessage());
      //e.printStackTrace(System.out);
    } catch (ConfigurationProblem e) {
      String message;
      if (e.getCause() != null) {
        message = String.format("Configuration error: %s. Reason: %s", e.getMessage(), e.getCause());
        System.out.println(e.getCause().getMessage());
        e.getCause().printStackTrace(System.out);
      } else {
        message = String.format("Configuration error: %s.", e.getMessage());
      }
      System.out.println(message);
      System.exit(1);
    }
  }

  private void parse(String[] args) throws ConfigurationProblem {
    if (args.length < 1) {
      throw new ConfigurationProblem("Usage: tealess [flags] address [port]");
    }
    // Main has no flag.
    Iterator<String> argsi = Arrays.asList(args).iterator();
    command = argsi.next();
    List<String> remaining = new LinkedList<>();
    while (argsi.hasNext()) {
      remaining.add(argsi.next());
    }
    this.args = remaining.toArray(new String[0]);
  }
}

