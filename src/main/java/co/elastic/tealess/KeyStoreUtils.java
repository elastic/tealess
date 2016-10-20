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

import co.elastic.Bug;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class KeyStoreUtils {
  public static List<Certificate> getTrustedCertificates(KeyStore keyStore) throws Bug {
    List<Certificate> trusted = new LinkedList<>();
    try {
      for (String alias : Collections.list(keyStore.aliases())) {
        trusted.add(keyStore.getCertificate(alias));
      }
    } catch (KeyStoreException e) {
      throw new Bug("Somethign went wrong while trying to iterate over the certificates in a keystore.", e);
    }
    return trusted;
  }
}
