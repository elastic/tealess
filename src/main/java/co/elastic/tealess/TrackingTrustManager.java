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

import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class TrackingTrustManager extends X509ExtendedTrustManagerProxy {
  private final SSLContextBuilder.SSLCertificateVerificationTracker tracker;

  public TrackingTrustManager(X509TrustManager trustManager, SSLContextBuilder.SSLCertificateVerificationTracker tracker) {
    super((X509ExtendedTrustManager) trustManager);
    this.tracker = tracker;
  }


  @Override
  public void checkClientTrusted(X509Certificate[] chain, String host, Socket socket) throws CertificateException {
    try {
      super.checkClientTrusted(chain, host, socket);
      this.tracker.track(chain, null, null);
    } catch (CertificateException e) {
      // XXX: Perhaps prompt if a user wants to accept?
      this.tracker.track(chain, null, e);
      throw e;
    }
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String host, Socket socket) throws CertificateException {
    // XXX: Check if Socket is an ObservableSSLSocket
    // XXX: If it is, we can tell the socket about ourselves so that the exception handler might know more details about the failure.

    try {
      super.checkServerTrusted(chain, host, socket);
      this.tracker.track(chain, null, null);
    } catch (CertificateException e) {
      // XXX: Perhaps prompt if a user wants to accept?
      this.tracker.track(chain, null, e);
      throw e;
    }
  }
}
