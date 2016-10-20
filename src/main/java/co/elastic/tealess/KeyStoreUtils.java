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
