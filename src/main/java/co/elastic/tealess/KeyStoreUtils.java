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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

class KeyStoreUtils {
  static final String RSA_PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
  static final String RSA_PEM_FOOTER = "-----END PRIVATE KEY-----";

  public static PrivateKey loadPrivateKeyPEM(Path path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

    List<String> lines = Files.readAllLines(path);
    List<String> keyLines = new LinkedList<>();

    // Look for the key entry
    boolean foundStart = false;
      for (String line : lines) {
      if (!foundStart) {
        if (line.equals(RSA_PEM_HEADER)) {
          foundStart = true;
          continue;
        }
      } else {
        if (line.equals(RSA_PEM_FOOTER)) {
          break;
        }
      }
      keyLines.add(line);
    }

    byte[] pkcs8bytes = Base64.getDecoder().decode(String.join("", keyLines).getBytes());

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

    PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(pkcs8bytes);
    return keyFactory.generatePrivate(pkcs8);
  }
}
