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

import co.elastic.tealess.cli.input.InvalidValue;

public class Setting<T> {
  private int argument = -1; // Nothing is an argument by default.

  public String getDescription() {
    return description;
  }

  public interface Validator<T> {
    ValidationResult validate(T value);
  }

  public interface Parser<T> {
    T parse(String text);
  }

  public interface InputHandler<T> extends Validator<T>, Parser<T> {
    // Empty
  }

  private final String name;
  private final String description;

  private T default_value;
  private T value;

  private Parser<T> parser;
  private Validator<T> validator;

  public Setting(String name, String description) {
    this.name = name;
    this.description = description;
  }

  public Setting(String name, String description, InputHandler<T> handler) {
    this(name, description);
    parseWith(handler);
    validateWith(handler);
  }

  public String getFlag() {
    return String.format("--%s", getName());
  }

  public Setting setDefaultValue(T value) {
    default_value = value;
    return this;
  }

  public T getDefaultValue() {
    return default_value;
  }

  public Setting parseWith(Parser<T> parser) {
    this.parser = parser;
    return this;
  }

  public Setting validateWith(Validator<T> validator) {
    this.validator = validator;
    return this;
  }

  public boolean isFlag(String text) {
    return getFlag().equals(text);
  }

  public T parse(String text) throws InvalidValue {
    T value = this.parser.parse(text);

    if (this.validator != null) {
      ValidationResult result = validator.validate(value);
      if (!result.isValid()) {
        throw new InvalidValue(String.format("Validation for %s failed. %s", getName(), result.getDetails()), value);
      }
    }

    this.value = value;
    return this.value;
  }

  public String getName() {
    return name;
  }

  public T getValue() {
    if (value != null) {
      return value;
    } else {
      return getDefaultValue();
    }
  }

  public Setting<T> asArgument(int i) {
    this.argument = i;
    return this;
  }

  public boolean isArgument() {
    return this.argument >= 0;
  }

}

