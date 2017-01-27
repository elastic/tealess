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
package co.elastic.tealess.protocol;

public enum ProtocolVersion {
  SSL_2_0(2, 0),
  SSL_3_0(3, 0),
  TLS_1_0(3, 1),
  TLS_1_1(3, 2),
  TLS_1_2(3, 3);

  private final int major;
  private final int minor;

  ProtocolVersion(int major, int minor) {
    this.major = major;
    this.minor = minor;
  }

  public static ProtocolVersion fromValues(int major, int minor) {
    if (major == 2 && minor == 0) {
      return SSL_2_0;
    } else if (major == 3 && minor == 0) {
      return SSL_3_0;
    } else if (major == 3 && minor == 1) {
      return TLS_1_0;
    } else if (major == 3 && minor == 2) {
      return TLS_1_1;
    } else if (major == 3 && minor == 3) {
      return TLS_1_2;
    }
    throw new IllegalArgumentException("major,minor (" + major + ", " + minor + ") is not valid.");
  }

  public String toString() {
    switch (this) {
      case SSL_2_0:
        return "SSL 2.0";
      case SSL_3_0:
        return "SSL 3.0";
      case TLS_1_0:
        return "TLS 1.0";
      case TLS_1_1:
        return "TLS 1.1";
      case TLS_1_2:
        return "TLS 1.2";
    }
    // We won't get here.
    return "Unknown";
  }
}

