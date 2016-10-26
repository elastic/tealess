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

import javax.net.ssl.KeyManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

class KeyStoreBuilder {
  private static final String keyManagerAlgorithm = KeyManagerFactory.getDefaultAlgorithm();

  // Based on some quick research, this appears to be the default java trust store location
  private static final String defaultTrustStorePath = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts").toString();

  // 'changeit' appears to be the default passphrase. I suppose it's ok. Or is it?!!!
  private static final char[] defaultTrustStorePassphrase = "changeit".toCharArray();

  private boolean modified;
  private KeyStore keyStore;
  private KeyManagerFactory keyManagerFactory;

  KeyStoreBuilder() throws NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException {
    keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, "hurray".toCharArray());
    keyManagerFactory = KeyManagerFactory.getInstance(keyManagerAlgorithm);
  }

  void useDefaultTrustStore() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
    useKeyStore(new File(defaultTrustStorePath), defaultTrustStorePassphrase);
    modified = true;
  }

  void addCAPath(Path path) throws CertificateException, FileNotFoundException, KeyStoreException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");

    FileInputStream in;
    in = new FileInputStream(path.toFile());

    int count = 0;
    for (Certificate cert : cf.generateCertificates(in)) {
      String alias = ((X509Certificate) cert).getSubjectX500Principal().toString();
      keyStore.setCertificateEntry(alias, cert);
      count++;
    }
    modified = true;
  }

  void useKeyStore(File path) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
    try {
      useKeyStore(path, defaultTrustStorePassphrase);
    } catch (IOException e) {
      if (e.getCause() instanceof UnrecoverableKeyException) {
        System.out.printf("Enter passphrase for keyStore %s: ", path);
        char[] passphrase = System.console().readPassword();
        useKeyStore(path, passphrase);
        Arrays.fill(passphrase, (char) 0);
      } else {
        throw e;
      }
      // Blank the passphrase for a little bit of extra safety; hoping it won't
      // live long in memory.
    }
  }

  void useKeyStore(File path, char[] passphrase) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
    FileInputStream fs;

    fs = new FileInputStream(path);
    keyStore.load(fs, passphrase);
    keyManagerFactory.init(keyStore, passphrase);

    //logger.info("Loaded keyStore with {} certificates: {}", keyStoreTrustedCertificates(keyStore).size(), path);
    modified = true;
  }

  KeyStore buildKeyStore() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
    if (!modified) {
      useDefaultTrustStore();
    }
    return keyStore;
  }

  KeyManagerFactory buildKeyManagerFactory() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
    buildKeyStore();
    return keyManagerFactory;
  }
}
