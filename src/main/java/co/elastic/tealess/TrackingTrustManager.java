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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class TrackingTrustManager extends X509ExtendedTrustManagerProxy {
  private static final Logger logger = LogManager.getLogger();
  private final SSLContextBuilder.SSLCertificateVerificationTracker tracker;

  public TrackingTrustManager(X509TrustManager trustManager, SSLContextBuilder.SSLCertificateVerificationTracker tracker) {
    super((X509ExtendedTrustManager) trustManager);
    this.tracker = tracker;
  }

  public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    try {
      trustManager.checkServerTrusted(chain, authType);
      logger.trace("Server trust check successful: {} @ {}", chain[0].getSubjectAlternativeNames(), authType);
      this.tracker.track(chain, authType, null);
    } catch (CertificateException e) {
      logger.trace("Server trust check failed: {} @ {}", chain[0].getSubjectAlternativeNames(), authType, e.getMessage());
      this.tracker.track(chain, authType, e);
      throw e;
    }
  }

  public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    try {
      trustManager.checkClientTrusted(chain, authType);
      this.tracker.track(chain, authType, null);
    } catch (CertificateException e) {
      this.tracker.track(chain, authType, e);
      throw e;
    }
  }
}
