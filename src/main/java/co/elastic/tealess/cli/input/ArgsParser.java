/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 default port is 443.");
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package co.elastic.tealess.cli.input;

import co.elastic.tealess.cli.Setting;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

public class ArgsParser {

  private static final Logger logger = LogManager.getLogger();

  public static ParserResult parse(List<Setting<?>> settings, List<Setting<?>> arguments, Iterator<String> args) {
    String firstArgument;
    int argi = 0;
    ParserResult result;

    while (args.hasNext()) {
      String entry = args.next();
      if (entry.equals("--")) {
        break;
      }

      if (entry.equals("--help")) {
        return ParserResult.help();
      }

      if (entry.startsWith("-")) {
        result = parseFlag(entry, args, settings, arguments);
        if (!result.getSuccess()) {
          return result;
        }
      } else {
        // First non-flag argument.
        result = parseArgument(arguments, argi, entry);
        argi++;
        if (!result.getSuccess()) {
          return result;
        }
        break;
      }
    }

    for (; args.hasNext(); argi++) {
      String text = args.next();
      result = parseArgument(arguments, argi, text);
      if (!result.getSuccess()) {
        return result;
      }
    }

    if (argi < arguments.size()) {
      return ParserResult.error("Missing required argument " + arguments.get(argi).getName());
    }

    return ParserResult.success();
  }

  private static ParserResult parseArgument(List<Setting<?>> arguments, int argi, String text) {
    if (argi >= arguments.size()) {
      return ParserResult.error(String.format("Too many arguments given. Extra argument: '%s' is not allowed.", text));
    }

    Setting<?> setting = arguments.get(argi);
    try {
      Object value = setting.parse(text);
      logger.debug("Argument '{}' with text '{}' parsed: {}", setting.getName(), text, value);
      return ParserResult.success();
    } catch (InvalidValue e) {
      return ParserResult.error(String.format("Invalid value for argument %s: %s\n  -> %s", setting.getName(), text, e));
    }

  }

  private static ParserResult parseFlag(String entry, Iterator<String> args, List<Setting<?>> settings, List<Setting<?>> arguments) {
    boolean flagFound = false;
    for (Setting<?> setting : settings) {
      if (arguments.contains(setting)) {
        // Don't process an argument setting as a flag.
        continue;
      }
      if (setting.isFlag(entry)) {
        flagFound = true;
        String text = args.next();
        try {
          Object value = setting.parse(text);
          logger.debug("Flag --{}={] parsed: {}", entry, text, value);
        } catch (InvalidValue e) {
          return ParserResult.error(String.format("Invalid value for flag %s: %s.\n  -> %s", setting.getName(), text, e));
        }
        break;
      }
    }

    if (!flagFound) {
      return ParserResult.error(String.format("Unknown flag: %s", entry));
    }

    return ParserResult.success();
  }

  public static void showHelp(String name, String preamble, List<Setting<?>> settings, List<Setting<?>> arguments) {
    System.out.println(preamble);
    String argsHelp = arguments.stream().map(Setting::getName).collect(Collectors.joining(" "));
    System.out.println("Usage: " + name + " [flags] " + argsHelp);

    System.out.println("Flags: ");
    for (Setting<?> setting : settings) {
      String lead = String.format("%s VALUE", setting.getFlag());
      System.out.printf("  %-20s %s", lead, setting.getDescription());
      if (setting.getDefaultValue() != null) {
        System.out.printf(" (default='%s')", setting.getDefaultValue());
      }
      System.out.println();
    }

    System.out.println("Arguments: ");
    for (Setting<?> setting : arguments) {
      String lead = String.format("%s VALUE", setting.getName());
      System.out.printf("  %-20s %s", lead, setting.getDescription());
      if (setting.getDefaultValue() != null) {
        System.out.printf(" (default='%s')", setting.getDefaultValue());
      }
      System.out.println();
    }
  }
}
