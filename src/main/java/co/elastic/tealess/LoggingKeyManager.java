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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

class LoggingKeyManager extends X509ExtendedKeyManager {
  private final X509ExtendedKeyManager keyManager;
  private final Logger logger = LogManager.getLogger();

  LoggingKeyManager(X509KeyManager km) {
    keyManager = (X509ExtendedKeyManager) km;
  }

  @Override
  public String[] getClientAliases(String keyType, Principal[] principals) {
    logger.info("KeyManager.getClientAliases()");
    return keyManager.getClientAliases(keyType, principals);
  }

  @Override
  public String chooseClientAlias(String[] keyType, Principal[] principals, Socket socket) {
    String result = keyManager.chooseClientAlias(keyType, principals, socket);
    logger.debug("KeyManager.chooseClientAlias() => '{}'");
    return result;
  }

  @Override
  public String[] getServerAliases(String keyType, Principal[] principals) {
    logger.info("KeyManager.getServerAliases()");
    return keyManager.getServerAliases(keyType, principals);
  }

  @Override
  public String chooseServerAlias(String keyType, Principal[] principals, Socket socket) {
    String result = keyManager.chooseServerAlias(keyType, principals, socket);
    logger.info("KeyManager.chooseServerAliases() => '{}'", result);
    return result;
  }

  @Override
  public X509Certificate[] getCertificateChain(String alias) {
    X509Certificate[] result = keyManager.getCertificateChain(alias);
    logger.info("Using client certificate alias '{}': {}", alias, result[0].getSubjectX500Principal());
    logger.trace("KeyManager.getCertificateChain(\"{}\") [chain length {}] [subject {}]", alias, result.length, result[0].getSubjectX500Principal());
    return result;
  }

  @Override
  public PrivateKey getPrivateKey(String alias) {
    PrivateKey result = keyManager.getPrivateKey(alias);
    logger.trace("KeyManager.getPrivateKey() => [type {}]", result.getAlgorithm());
    return result;
  }

  @Override
  public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
    String result = keyManager.chooseEngineClientAlias(keyType, issuers, engine);
    logger.trace("KeyManager.chooseEngineClientAlias() => '{}'", result);
    return result;
  }
}
