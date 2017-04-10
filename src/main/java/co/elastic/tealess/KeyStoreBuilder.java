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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.KeyManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collection;

public class KeyStoreBuilder {
  private static final String keyManagerAlgorithm = KeyManagerFactory.getDefaultAlgorithm();

  // Based on some quick research, this appears to be the default java trust store location
  public static final Path defaultTrustStorePath = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");

  // 'changeit' appears to be the default passphrase. I suppose it's ok. Or is it?!!!
  private static final char[] defaultTrustStorePassphrase = "changeit".toCharArray();

  private boolean modified;
  private KeyStore keyStore;
  private KeyManagerFactory keyManagerFactory;
  private static final Logger logger = LogManager.getLogger();

  // the "hurray" passphrase is only to satisfy the KeyStore.load API
  // (requires a passphrase, even when loading null).
  private final char[] IN_MEMORY_KEYSTORE_PASSPHRASE = "hurray".toCharArray();

  public KeyStoreBuilder() throws NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException {
    keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    // default to an empty KeyStore instance.
    keyStore.load(null, IN_MEMORY_KEYSTORE_PASSPHRASE);
    keyManagerFactory = KeyManagerFactory.getInstance(keyManagerAlgorithm);
  }

  void useDefaultTrustStore() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
    logger.trace("Using default trust store: {}", defaultTrustStorePath);
    useKeyStore(defaultTrustStorePath.toFile(), defaultTrustStorePassphrase);
    modified = true;
  }

  // XXX: This only supports RSA keys right now.
  public void addPrivateKeyPEM(Path keyPath, Path certificatePath) throws IOException, Bug, ConfigurationProblem {
    PrivateKey key = null;
    try {
      key = KeyStoreUtils.loadPrivateKeyPEM(keyPath);
    } catch (NoSuchAlgorithmException e) {
      throw new Bug("Unexpected problem when loading private key.", e);
    } catch (InvalidKeySpecException e) {
      throw new Bug("Unexpected problem when loading private key.", e);
    }
    Collection<? extends Certificate> certificates = null;
    try {
      certificates = parseCertificatesPath(certificatePath);
    } catch (CertificateException e) {
      throw new ConfigurationProblem("Failure loading certificates from " + certificatePath, e);
    }
    try {
      logger.info("Adding key+cert named '{}' to internal keystore.", "mykey");
      keyStore.setKeyEntry("mykey", key, IN_MEMORY_KEYSTORE_PASSPHRASE, certificates.toArray(new Certificate[0]));
      keyManagerFactory.init(keyStore, IN_MEMORY_KEYSTORE_PASSPHRASE);
    } catch (KeyStoreException e) {
      throw new Bug("Failure trying to setKeyEntry in the in-memory keystore", e);
    } catch (UnrecoverableKeyException e) {
      throw new Bug("Corrupt or invalid keystore passphrase? This is a bug (since we are forming the keystore in-memory!", e);
    } catch (NoSuchAlgorithmException e) {
      throw new Bug("No such algorithm?", e);
    }
    modified = true;
  }

  public void addCAPath(Path path) throws CertificateException, IOException, KeyStoreException {
    if (path == null) {
      throw new NullPointerException("path must not be null");
    }

    if (Files.isDirectory(path)) {
      logger.info("Adding all files in {} to trusted certificate authorities.", path);
      for (File file : path.toFile().listFiles()) {
        if (file.isFile()) {
          addCAPath(file);
        } else {
          logger.info("Ignoring non-file '{}'", file);
        }
      }
    } else{
      addCAPath(path.toFile());
    }
  }

  void addCAPath(File file) throws CertificateException, IOException, KeyStoreException {
    for (Certificate cert : parseCertificatesPath(file.toPath())) {
      logger.debug("Loaded certificate from {}: {}", file, ((X509Certificate)cert).getSubjectX500Principal());
      String alias = ((X509Certificate) cert).getSubjectX500Principal().toString();
      keyStore.setCertificateEntry(alias, cert);
    }
    modified = true;
  }

  Collection<? extends Certificate> parseCertificatesPath(Path path) throws IOException, CertificateException {
    FileInputStream in = new FileInputStream(path.toFile());
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    try {
      return cf.generateCertificates(in);
    } finally {
      in.close();
    }
  }

  public void useKeyStore(File path) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
    try {
      useKeyStore(path, defaultTrustStorePassphrase);
    } catch (IOException e) {
      if (e.getCause() instanceof UnrecoverableKeyException) {
        System.out.printf("Enter passphrase for keyStore %s: ", path);
        char[] passphrase = System.console().readPassword();
        useKeyStore(path, passphrase);

        // Make an effort to not keep the passphrase in-memory longer than necessary? Maybe?
        // This may not matter, anyway, since I'm pretty sure KeyManagerFactor.init() keeps it anyway...
        Arrays.fill(passphrase, (char) 0);
      } else {
        throw e;
      }
    }
  }

  void useKeyStore(File path, char[] passphrase) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
    FileInputStream fs;

    fs = new FileInputStream(path);
    keyStore.load(fs, passphrase);
    keyManagerFactory.init(keyStore, passphrase);

    logger.info("Loaded keyStore with {} certificates: {}", (keyStore).size(), path);
    modified = true;
  }

  public KeyStore buildKeyStore() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
    if (!modified) {
      useDefaultTrustStore();
    }
    logger.trace("Returning non-default keystore");
    return keyStore;
  }

  public KeyManagerFactory buildKeyManagerFactory() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
    buildKeyStore();
    return keyManagerFactory;
  }
}
