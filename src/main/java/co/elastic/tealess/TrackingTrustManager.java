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

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class TrackingTrustManager implements X509TrustManager {
  private final X509TrustManager tm;
  private SSLContextBuilder.SSLCertificateVerificationTracker tracker;

  public TrackingTrustManager(X509TrustManager tm) {
    this.tm = tm;
  }

  public void setTracker(SSLContextBuilder.SSLCertificateVerificationTracker tracker) {
    this.tracker = tracker;
  }

  public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    try {
      tm.checkServerTrusted(chain, authType);
    } catch (CertificateException e) {
      if (tracker != null) {
        this.tracker.track(chain, authType, e);
      }
      throw e;
    }
    if (tracker != null) {
      this.tracker.track(chain, authType, null);
    }
  }

  public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    try {
      tm.checkClientTrusted(chain, authType);
    } catch (CertificateException e) {
      if (tracker != null) {
        this.tracker.track(chain, authType, e);
      }
      throw e;
    }
    if (tracker != null) {
      this.tracker.track(chain, authType, null);
    }
  }

  public X509Certificate[] getAcceptedIssuers() {
    return tm.getAcceptedIssuers();
  }
}
