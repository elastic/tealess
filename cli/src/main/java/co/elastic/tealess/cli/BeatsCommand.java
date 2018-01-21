package co.elastic.tealess.cli;

import co.elastic.tealess.*;
import co.elastic.tealess.cli.beats.MapUtil;
import co.elastic.tealess.cli.input.ArgsParser;
import co.elastic.tealess.cli.input.InetSocketAddressInput;
import co.elastic.tealess.cli.input.PathInput;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Created by jls on 4/6/2017.
 */
public class BeatsCommand implements Command {
  private static final Logger logger = LogManager.getLogger();
  private static final String DESCRIPTION = "Test TLS settings from an Elastic Beats configuration.";
  // Beats output configuration sections to analyze.
  private final String[] outputs = {"logstash", "elasticsearch", "redis", "kafka"};
  private Path settingsPath = null;

  private void setSettingsPath(Path path) {
    settingsPath = path;
  }

  @Override
  public ArgsParser getParser() {
    return new ArgsParser()
            .setDescription(DESCRIPTION)
            .addPositional(new Setting<>("settings", "The path to the beats yaml", PathInput.singleton), this::setSettingsPath);
  }

  @Override
  public void run() throws ConfigurationProblem, Bug {
    Yaml yaml = new Yaml();
    Map<String, Object> settings;
    try {
      settings = (Map<String, Object>) yaml.load(new FileReader(settingsPath.toFile()));
    } catch (FileNotFoundException e) {
      throw new ConfigurationProblem("The specified configuration file does not exist:" + settingsPath, e);
    }

    Map<String, Object> flatSettings = MapUtil.flattenMap(settings);
    for (String output : outputs) {
      if (flatSettings.keySet().stream().anyMatch(key -> key.startsWith("output." + output + ".ssl"))) {
        System.out.println("Checking " + output + " output in " + settingsPath);
        check(flatSettings, "output." + output);
      }
    }
  }

  private void check(Map<String, Object> flatSettings, String settingsPrefix) throws ConfigurationProblem, Bug {
    final KeyStoreBuilder keys;
    final KeyStoreBuilder trust;
    try {
      keys = new KeyStoreBuilder();
      trust = new KeyStoreBuilder();
    } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
      throw new Bug("'new KeyStoreBuilder' failed", e);
    }

    processCertificateAuthorities(flatSettings, settingsPrefix, trust);
    processClientCertificate(flatSettings, settingsPrefix, keys);

    SSLContextBuilder cb = new SSLContextBuilder();
    try {
      cb.setTrustStore(trust.buildKeyStore());
      cb.setKeyManagerFactory(keys.buildKeyManagerFactory());
    } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
      throw new Bug("Failed building keystores", e);
    }

    SSLChecker checker;
    try {
      checker = new SSLChecker(cb);
    } catch (KeyManagementException | KeyStoreException | NoSuchAlgorithmException e) {
      throw new ConfigurationProblem("Failed to build tealess context.", e);
    }


    // XXX: the 'elasticsearch' output supports URLs. Probably should handle this.
    InetSocketAddressInput addressInput = new InetSocketAddressInput(-1); // no default port
    for (String address : ((List<String>) flatSettings.get(settingsPrefix + ".hosts"))) {
      Collection<InetAddress> addresses;
      InetSocketAddress inetAddress = addressInput.parse(address);

      if (inetAddress.getPort() == -1) {
        throw new ConfigurationProblem("No port given for host " + address);
      }

      String hostname = inetAddress.getHostString();

      try {
        logger.trace("Doing name resolution on {}", hostname);
        addresses = Resolver.SystemResolver.resolve(hostname);
      } catch (UnknownHostException e) {
        throw new ConfigurationProblem("Unknown host", e);
      }

      System.out.printf("%s resolved to %d addresses\n\n", hostname, addresses.size());
      List<SSLReport> reports = addresses.stream()
              .map(a -> checker.check(new InetSocketAddress(a, inetAddress.getPort()), hostname))
              .collect(Collectors.toList());

      SSLReportAnalyzer.analyzeMany(reports);
    }
  }

  private void processClientCertificate(Map<String, Object> flatSettings, String settingsPrefix, KeyStoreBuilder keys) throws ConfigurationProblem, Bug {
    logger.info("{}", (new Yaml()).dump(flatSettings));
    String certificateKey = settingsPrefix + ".ssl.certificate";

    // I paused for a moment after typing the next variable name. I needed to reflect on how my past choices
    // had lead to me naming a variable so strangely.
    String keyKey = settingsPrefix + ".ssl.key";

    if (flatSettings.containsKey(certificateKey) && !flatSettings.containsKey(keyKey)) {
      throw new ConfigurationProblem("When " + certificateKey + " is set, you must also set " + keyKey);
    }
    if (flatSettings.containsKey(keyKey) && !flatSettings.containsKey(certificateKey)) {
      throw new ConfigurationProblem("When " + keyKey + " is set, you must also set " + certificateKey);
    }

    logger.info("{} / {}", keyKey, certificateKey);
    logger.info("{}: {}", keyKey, flatSettings.containsKey(keyKey));
    logger.info("{}: {}", certificateKey, flatSettings.containsKey(certificateKey));
    if (!(flatSettings.containsKey(keyKey) && flatSettings.containsKey(certificateKey))) {
      logger.info("Skipping optional client certificate setup because configuration did not include one.");
      return;
    }

    Path keyPath = new File((String) flatSettings.get(keyKey)).toPath();
    Path certificatePath = new File((String) flatSettings.get(certificateKey)).toPath();
    try {
      keys.addPrivateKeyPEM(keyPath, certificatePath);
    } catch (IOException e) {
      throw new ConfigurationProblem("Problem occurred when reading client certificate and key.", e);
    }
  }

  private void processCertificateAuthorities(Map<String, Object> flatSettings, String settingsPrefix, KeyStoreBuilder trust) throws ConfigurationProblem, Bug {
    String certificateAuthoritiesKey = settingsPrefix + ".ssl.certificate_authorities";
    if (flatSettings.containsKey(certificateAuthoritiesKey)) {
      List<String> caPaths = (List<String>) flatSettings.get(certificateAuthoritiesKey);

      for (String path : caPaths) {
        try {
          trust.addCAPath(new File(path).toPath());
        } catch (CertificateException e) {
          throw new ConfigurationProblem("Failed trying to load certificate authority file: " + path, e);
        } catch (FileNotFoundException e) {
          throw new ConfigurationProblem("Certificate authority setting (" + certificateAuthoritiesKey + ") lists a file that does not exist: " + path);
        } catch (IOException e) {
          throw new ConfigurationProblem("An IO error occurred while reading certificate authorities from " + path, e);
        } catch (KeyStoreException e) {
          throw new Bug("Unexpected key store problem", e);
        }
      }
    }
  }
}
