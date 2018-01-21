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

/**
 * Created by jls on 11/16/16.
 */
public class ParserResult {
  private final String details;
  private boolean success = true;
  private Throwable exception;

  private ParserResult(boolean success, String details) {
    this.success = success;
    this.details = details;
  }

  private ParserResult(String details, Throwable exception) {
    this(false, details);
    this.exception = exception;
  }


  public static ParserResult error(String details) {
    return new ParserResult(false, details);
  }

  public static ParserResult help() {
    return new ParserResult(false, null);
  }

  public static ParserResult success() {
    return new ParserResult(true, null);
  }

  public static ParserResult error(String details, Throwable exception) {
    return new ParserResult(details, exception);
  }

  public boolean getSuccess() {
    return success;
  }

  public String getDetails() {
    return details;
  }

  public Throwable getException() {
    return exception;
  }
}
