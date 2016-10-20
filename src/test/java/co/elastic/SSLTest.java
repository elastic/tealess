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

package co.elastic;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import co.elastic.tealess.SSLChecker;

import java.security.KeyStore;

public class SSLTest {
  //@Test
  public void hasFun() throws Exception {
    String keystore_path = "./foo.jks";
    char[] passphrase = "foobar".toCharArray();

    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

    //FileInputStream fs = new FileInputStream(keystore_path);
    //ks.load(fs, passphrase);

    SSLChecker diag = new SSLChecker(ks, ks);

    String hostname = "www.semicomplete.com";

    for (InetAddress address : Resolver.SystemResolver.resolve(hostname)) {
      try {
        diag.check(new InetSocketAddress(address, 443), hostname);
      } catch (Exception e) {
        System.err.printf("Failed: {}\n", e);
      }
    }
  }
}

