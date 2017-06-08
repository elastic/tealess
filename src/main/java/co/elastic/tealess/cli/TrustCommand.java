package co.elastic.tealess.cli;

import co.elastic.Bug;
import co.elastic.tealess.*;
import co.elastic.tealess.cli.input.ArgsParser;
import co.elastic.tealess.cli.input.InetSocketAddressInput;
import co.elastic.tealess.cli.input.ParserResult;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Created by jls on 6/5/2017.
 */
public class TrustCommand implements Command {
  private static final String OPENSSL_CERTIFICATE_HEADER = "-----BEGIN CERTIFICATE-----";
  private static final String OPENSSL_CERTIFICATE_FOOTER = "-----END CERTIFICATE-----";
  private static final String PACKAGE_LOGGER_NAME = "co.elastic";
  private static final Logger logger = LogManager.getLogger();
  private static final String DESCRIPTION = "Fetch a remote server's ssl certificate and save it locally.";

  private static final Base64.Encoder b64encoder = Base64.getMimeEncoder();

  private final ArgsParser parser = new ArgsParser();
  //private final Setting<Path> capath = parser.addNamed(new Setting<>("capath", "The path to a file containing one or more certificates to trust in PEM format.", PathInput.singleton));

  private final Setting<Path> trustStore = parser.addNamed(new Setting<>("truststore", "The path to a java keystore or pkcs12 file to save any retrieved certificates"))
    .parseWith(Paths::get);
  private final Setting<Path> pemPath = parser.addNamed(new Setting<>("pem", "The path to a file to write the PEM-formatted certificate chain"))
    .parseWith(Paths::get);
  private final Setting<Level> logLevel = parser.addNamed(new Setting<Level>("log-level", "The log level"))
    .setDefaultValue(Level.WARN)
    .parseWith(Level::valueOf);
  private final Setting<InetSocketAddress> address = parser.addPositional(new Setting<>("address", "The address in form of `host` or `host:port` to connect", new InetSocketAddressInput(443)));

  @Override
  public ParserResult parse(String[] args) {
    parser.setDescription(DESCRIPTION);
    ParserResult result = parser.parse(args);
    if (!result.getSuccess()) {
      if (result.getDetails() != null) {
        System.out.println(result.getDetails());
        System.out.println();
      }
      parser.showHelp("trust");
      return result;
    }

    System.out.printf("Log level: %s\n", logLevel.getValue());
    if (logLevel.getValue() != null) {
      LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
      ctx.getConfiguration().getLoggerConfig(PACKAGE_LOGGER_NAME).setLevel(logLevel.getValue());
      ctx.updateLoggers();
    }

    return result;
  }

  @Override
  public void run() throws ConfigurationProblem, Bug {
    final SSLChecker checker = getSSLChecker();
    final List<SSLReport> reports = checker.checkAll(address.getValue());

    for (SSLReport report : reports) {
      if (!report.success()) {
        logger.error("Failed SSL connection to {}", report.getAddress());
        continue;
      }

      final PeerCertificateDetails peerCertificateDetails = report.getPeerCertificateDetails();
      if (peerCertificateDetails.getException() != null) {
        logger.info("No certificates for {} because {}", report.getAddress(), peerCertificateDetails.getException().getMessage());
        continue;
      }

      final X509Certificate[] chain = peerCertificateDetails.getChain();
      System.out.println("Trust: " + trustStore.getValue());
      System.out.println("PEM: " + pemPath.getValue());

      if (pemPath.getValue() == null && trustStore.getValue() == null) {
        writePEM(System.out, chain);
      } else {
        if (pemPath.getValue() != null) {
          writePEM(pemPath.getValue(), chain);
        }

        if (trustStore.getValue() != null) {
          writeTrustStore(trustStore.getValue(), chain, report.getAddress());
        }

      }
    }
  }

  private static void writeTrustStore(Path path, X509Certificate[] chain, InetSocketAddress address) throws Bug, ConfigurationProblem {
    KeyStoreBuilder ksb;

    try {
      ksb = new KeyStoreBuilder();
    } catch (NoSuchAlgorithmException | IOException | CertificateException | KeyStoreException | UnrecoverableKeyException e) {
      throw new Bug("Failed to create KeyStoreBuilder", e);
    }

    if (Files.exists(path)) {
      try {
        ksb.useKeyStore(path.toFile());
      } catch (NoSuchAlgorithmException e) {
        throw new Bug("Failed to load keystore.", e);
      } catch (IOException | CertificateException | KeyStoreException | UnrecoverableKeyException e) {
        throw new ConfigurationProblem("Failed to load keystore", e);
      }
    } else {
      try {
        ksb.empty();
      } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
        throw new Bug("Failed to create empty keystore", e);
      }
    }

    final KeyStore keyStore;
    try {
      keyStore = ksb.buildKeyStore();
    } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
      throw new Bug("Failed to build keystore in memory", e);
    } catch (UnrecoverableKeyException e) {
      throw new ConfigurationProblem(e.getMessage(), e);
    }


    // Add the certificate chain to the key store
    for (int i = 0; i < chain.length; i++) {
      String alias = String.format("%s[%d]", address, i);
      try {
        keyStore.setCertificateEntry(alias, chain[i]);
      } catch (KeyStoreException e) {
        throw new Bug("Failed to add certificate to key store", e);
      }
    }

    System.out.printf("Enter passphrase for keyStore %s: ", path);
    char[] passphrase = System.console().readPassword();
    System.out.printf("Confirm passphrase for keyStore %s: ", path);
    char[] passphrase2 = System.console().readPassword();

    if (Arrays.equals(passphrase, passphrase2)) {
      try (OutputStream out = new FileOutputStream(path.toFile())) {
        keyStore.store(out, passphrase);
      } catch (IOException | KeyStoreException | CertificateException e) {
        throw new ConfigurationProblem("Failed to write keystore", e);
      } catch (NoSuchAlgorithmException e) {
        throw new Bug("Failed to write keystore " + path, e);
      }
    } else {
      logger.error("Passphrases did not match. Cannot write to {}", path);
    }
  }

  private static void writePEM(Path path, X509Certificate[] chain) throws ConfigurationProblem {
    try (PrintStream out = new PrintStream(new FileOutputStream(path.toFile(), true))) {
      writePEM(out, chain);
    } catch (FileNotFoundException e) {
      throw new ConfigurationProblem("Could not write to " + path + ": " + e);
    }
  }

  private static void writePEM(PrintStream out, X509Certificate[] chain) {
    byte[] encoded;
    for (X509Certificate certificate : chain) {
      try {
        encoded = certificate.getEncoded();
      } catch (CertificateEncodingException e) {
        e.printStackTrace();
        continue;
      }
      out.println(OPENSSL_CERTIFICATE_HEADER);
      out.println(b64encoder.encodeToString(encoded));
      out.println(OPENSSL_CERTIFICATE_FOOTER);
    }
  }

  private SSLChecker getSSLChecker() throws Bug, ConfigurationProblem {
    final KeyStoreBuilder keys;
    final KeyStoreBuilder trust;

    try {
      keys = new KeyStoreBuilder();
      trust = new KeyStoreBuilder();
    } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
      throw new Bug("'new KeyStoreBuilder' failed", e);
    }

    final SSLContextBuilder cb = new SSLContextBuilder();
    try {
      cb.setTrustStore(trust.buildKeyStore());
      cb.setKeyManagerFactory(keys.buildKeyManagerFactory());
    } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
      throw new Bug("Failed building keystores", e);
    }

    final SSLChecker checker;
    try {
      checker = new SSLChecker(cb);
    } catch (KeyManagementException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
      throw new ConfigurationProblem("Failed to build tealess context.", e);
    }
    return checker;
  }
}
