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

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class ArgsParser {
  private static final Logger logger = LogManager.getLogger();

  public interface TryConsumer<T> {
    void accept(T t) throws Exception;
  }

  private class Entry<T> implements Parser<T>, TryConsumer<T> {
    private Setting<T> setting;
    private TryConsumer<T> consumer;

    public Entry(Setting<T> setting, TryConsumer<T> consumer) {
      this.setting = setting;
      this.consumer = consumer;
    }

    public T parse(String text) throws InvalidValue {
      T value = setting.parse(text);
      try {
        consumer.accept(value);
      } catch (Exception e) {
        throw new InvalidValue("Given value " + value + " is not acceptable for " + setting.getName(), e);
      }
      return value;
    }

    public void accept(T value) throws Exception {
      consumer.accept(value);
    }

    public Setting<T> getSetting() {
      return setting;
    }
  }

  private List<Entry<?>> namedSettings = new LinkedList<>();
  private List<Entry<?>> positionalSettings = new LinkedList<>();
  private String description;

  public ArgsParser setDescription(String description) {
    this.description = description;
    return this;
  }

  public <T> ArgsParser addNamed(Setting<T> setting, TryConsumer<T> consumer) {
    namedSettings.add(new Entry<>(setting, consumer));
    return this;
  }

  public <T> ArgsParser addPositional(Setting<T> setting, TryConsumer<T> consumer) {
    positionalSettings.add(new Entry<>(setting, consumer));
    return this;
  }

  public ParserResult parse(String[] args) {
    return parse(Arrays.asList(args).iterator());
  }

  public ParserResult parse(Iterator<String> args) {
    int argi = 0;
    ParserResult result;

    while (args.hasNext()) {
      String input = args.next();
      if (input.equals("--")) {
        break;
      }

      if (input.equals("--help")) {
        return ParserResult.help();
      }

      if (input.startsWith("-")) {
        result = parseFlag(input, args, namedSettings, positionalSettings);
        if (!result.getSuccess()) {
          return result;
        }
      } else {
        // First non-flag argument.
        result = parsePositional(positionalSettings, argi, input);
        argi++;
        if (!result.getSuccess()) {
          return result;
        }
        break;
      }
    }

    for (; args.hasNext(); argi++) {
      String text = args.next();
      result = parsePositional(positionalSettings, argi, text);
      if (!result.getSuccess()) {
        return result;
      }
    }

    if (argi < positionalSettings.size()) {
      return ParserResult.error("Missing required argument " + positionalSettings.get(argi).getSetting().getName());
    }

    return ParserResult.success();
  }

  private static ParserResult parsePositional(List<Entry<?>> positionalSettings, int argi, String text) {
    if (argi >= positionalSettings.size()) {
      return ParserResult.error(String.format("Too many arguments given. Extra argument: '%s' is not allowed.", text));
    }

    Entry<?> entry = positionalSettings.get(argi);
    try {
      Object value = entry.parse(text);
      logger.debug("Argument '{}' with text '{}' parsed: {}", entry.getSetting().getName(), text, value);
      return ParserResult.success();
    } catch (InvalidValue e) {
      return ParserResult.error(String.format("Invalid value for argument %s: %s\n  -> %s", entry.getSetting().getName(), text, e));
    }
  }

  private static ParserResult parseFlag(String input, Iterator<String> args, List<Entry<?>> namedSettings, List<Entry<?>> positionalSettings) {
    boolean flagFound = false;
    for (Entry<?> entry : namedSettings) {
      if (positionalSettings.contains(entry)) {
        // Don't process an argument setting as a flag.
        continue;
      }

      Setting<?> setting = entry.getSetting();
      if (setting.isFlag(input)) {
        flagFound = true;
        String flagInput = args.next();
        try {
          Object value = entry.parse(flagInput);
          logger.debug("Flag --{}={] parsed: {}", entry, flagInput, value);
        } catch (InvalidValue e) {
          return ParserResult.error(String.format("Invalid value for flag %s: %s.\n  -> %s", entry.getSetting().getName(), flagInput, e));
        }
        break;
      }
    }

    if (!flagFound) {
      return ParserResult.error(String.format("Unknown flag: %s", input));
    }

    return ParserResult.success();
  }

  public void showHelp(String name) {
    showHelp(name, description, namedSettings, positionalSettings);
  }

  private static void showHelp(String name, String preamble, List<Entry<?>> namedSettings, List<Entry<?>> positionalSettings) {
    System.out.println(preamble);
    String argsHelp = positionalSettings.stream().map(Entry::getSetting).map(Setting::getName).collect(Collectors.joining(" "));
    System.out.println("Usage: " + name + " [flags] " + argsHelp);

    System.out.println("Flags: ");
    for (Entry<?> entry : namedSettings) {
      Setting setting = entry.getSetting();
      String lead = String.format("%s VALUE", setting.getFlag());
      System.out.printf("  %-20s %s", lead, setting.getDescription());
      if (setting.getDefaultValue() != null) {
        System.out.printf(" (default='%s')", setting.getDefaultValue());
      }
      System.out.println();
    }

    System.out.println("Arguments: ");
    for (Entry<?> entry : positionalSettings) {
      Setting setting = entry.getSetting();
      String lead = String.format("%s VALUE", setting.getName());
      System.out.printf("  %-20s %s", lead, setting.getDescription());
      if (setting.getDefaultValue() != null) {
        System.out.printf(" (default='%s')", setting.getDefaultValue());
      }
      System.out.println();
    }
  }
}
