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

package co.elastic.tealess.cli.input;

import co.elastic.tealess.ConfigurationProblem;
import co.elastic.tealess.cli.Setting;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.reflect.Field;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * Created by jls on 10/27/16.
 */
public class ArgsParser {
  private static final Logger logger = LogManager.getLogger();

  public static List<String> parseFlags(List<Setting<?>> settings, Iterator<String> args) throws ConfigurationProblem {
    List<String> parameters = new LinkedList<>();
    while (args.hasNext()) {
      String entry = args.next();
      if (entry.equals("--")) {
        break;
      }

      if (!entry.startsWith("-")) {
        parameters.add(entry); // first non-flag argument
        break;
      }

      if (entry.equals("--help")) {
        parameters.add("--help");
        return parameters;
      }

      boolean flagFound = false;
      for (Setting<?> setting : settings) {
        if (setting.isFlag(entry)) {
          flagFound = true;
          String text = args.next();
          try {
            Object value = setting.parse(text);
            logger.debug("Flag --{}={] parsed: {}", entry, text, value);
          } catch (InvalidValue e) {
            throw new ConfigurationProblem(String.format("Invalid value for flag %s: %s", setting.getName(), text), e);
          }
          break;
        }
      }

      if (!flagFound) {
        throw new ConfigurationProblem(String.format("Unknown flag: %s", entry));
      }
    }

    while (args.hasNext()) {
      parameters.add(args.next());
    }
    return parameters;
  }

  public static List<Setting<?>> getSettings(Object o) throws ConfigurationProblem {
    List<Setting<?>> settings = new LinkedList<>();

    try {
      Field[] fields = o.getClass().getDeclaredFields();
      for (Field field : fields) {
        if (Setting.class.isAssignableFrom(field.getType())) {
          settings.add((Setting<?>) field.get(o));
        }
      }
    } catch (IllegalAccessException e) {
      throw new ConfigurationProblem("Failed to parse flags because the security manager prevented us from using reflection to look for fields of type Setting");
    }

    return settings;
  }

  public static void showHelp(Object o) throws ConfigurationProblem {
    System.out.println("Tealess is a tool for figuring out why an SSL/TLS handshake fails");
    System.out.println();
    System.out.println("Usage: tealess [flags] address [port=443]");
    System.out.println("Flags: ");

    for (Setting<?> setting : getSettings(o)) {
      String lead = String.format("%s VALUE", setting.getFlag());
      System.out.printf("  %-20s %s", lead, setting.getDescription());
      if (setting.getDefaultValue() != null) {
        System.out.printf(" (default='%s')", setting.getDefaultValue());
      }
      System.out.println();
    }
  }
}
