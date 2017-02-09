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

package co.elastic.tealess.cli.environment;

import co.elastic.tealess.cli.EnvironmentCommand;

import java.util.LinkedList;
import java.util.List;

/**
 * Created by jls on 2/2/17.
 */
public class CipherSuite implements Comparable<CipherSuite> {
  String name;
  boolean enabled;
  boolean java;
  boolean tcnative;

  public CipherSuite(String name, boolean enabled, boolean java, boolean tcnative) {
    this.name = name;
    this.enabled = enabled;
    this.java = java;
    this.tcnative = tcnative;
  }

  public String toString() {
    List<String> support = new LinkedList<>();
    if (java) {
      support.add("java");
    }
    if (tcnative) {
      support.add("tcnative");
    }

    return String.format("%s %s (%s)", enabled ? "+" : " ", name, String.join(", ", support));
  }

  @Override
  public int compareTo(CipherSuite cipherSuite) {
    return name.compareTo(cipherSuite.name);
  }
}
