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

import java.security.cert.X509Certificate;

public class PeerCertificateDetails {
  private final X509Certificate[] chain;
  private final String authType;
  private final Throwable exception;

  public PeerCertificateDetails(X509Certificate[] chain, String authType, Throwable exception) {
    this.chain = chain;
    this.authType = authType;
    this.exception = exception;
  }

  public X509Certificate[] getChain() {
    return chain;
  }

  public String getAuthType() {
    return authType;
  }

  public Throwable getException() {
    return exception;
  }
}
