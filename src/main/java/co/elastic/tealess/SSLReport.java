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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.net.InetSocketAddress;

public class SSLReport {
  private Throwable exception;
  private SSLContext sslContext;
  private SSLSession sslSession;
  private InetSocketAddress address;
  private PeerCertificateDetails peerCertificateDetails;
  private String hostname;
  private boolean hostnameVerified;
  private long timeout;

  SSLReport() {
    // Nothing
  }

  String getHostname() {
    return hostname;
  }

  void setHostname(String hostname) {
    this.hostname = hostname;
  }

  public InetSocketAddress getAddress() {
    return address;
  }

  void setAddress(InetSocketAddress address) {
    this.address = address;
  }

  void setFailed(Throwable e) {
    exception = e;
  }

  SSLContext getSSLContext() {
    return sslContext;
  }

  void setSSLContext(SSLContext ctx) {
    sslContext = ctx;
  }

  SSLSession getSSLSession() {
    return sslSession;
  }

  void setSSLSession(SSLSession s) {
    sslSession = s;
  }

  public PeerCertificateDetails getPeerCertificateDetails() {
    return peerCertificateDetails;
  }

  void setPeerCertificateDetails(PeerCertificateDetails details) {
    peerCertificateDetails = details;
  }

  public Throwable getException() {
    return exception;
  }

  void setHostnameVerified(boolean verified) {
    hostnameVerified = verified;
  }
  
  boolean getHostnameVerified() {
    return hostnameVerified;
  }
  
  public boolean success() {
    return exception == null;
  }

  public void setTimeout(long timeout) {
    this.timeout = timeout;
  }

  public long getTimeout() {
    return timeout;
  }
}
