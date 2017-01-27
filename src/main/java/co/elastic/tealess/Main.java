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

import co.elastic.tealess.cli.Command;
import co.elastic.tealess.cli.ConnectCommand;
import co.elastic.tealess.cli.input.ParserResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

class Main {
  private static final String PACKAGE_LOGGER_NAME = "co.elastic";
  private static final Logger logger = LogManager.getLogger();

  private String command;
  private String[] args;

  public static void main(String[] args) throws Exception {
    String commandName = args[0];

    Command command;

    switch (commandName) {
      case "connect":
        command = new ConnectCommand();
        break;
      default:
        System.out.printf("Unknown command: '%s'\n", commandName);
        System.exit(1);
        return;
    }

    try {
      // Remove args[0] from args.
      args = Arrays.stream(args).skip(1).toArray(String[]::new);
      ParserResult result = command.parse(args);
      if (!result.getSuccess()) {
        if (result.getDetails() != null) {
          System.out.println("Problem: " + result.getDetails());
          if (result.getException() != null) {
            result.getException().printStackTrace(System.out);
          }
          System.exit(1);
        }
        return;
      }
      command.run();
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

