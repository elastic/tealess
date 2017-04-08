package co.elastic.tealess.cli;

import co.elastic.Blame;
import co.elastic.Bug;
import co.elastic.Resolver;
import co.elastic.tealess.*;
import co.elastic.tealess.cli.input.ArgsParser;
import co.elastic.tealess.cli.input.InetSocketAddressInput;
import co.elastic.tealess.cli.input.ParserResult;
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
  public static final String DESCRIPTION = "Test TLS settings from an Elastic Beats configuration.";

  private final ArgsParser parser = new ArgsParser();
  private final Setting<Path> settingsPath = parser.addPositional(new Setting<Path>("settings", "The path to the beats yaml", PathInput.singleton));

  @Override
  public ParserResult parse(String[] args) throws ConfigurationProblem {
    parser.setDescription(DESCRIPTION);
    ParserResult result = parser.parse(args);
    if (!result.getSuccess()) {
      if (result.getDetails() != null) {
        System.out.println(result.getDetails());
        System.out.println();
      }
      parser.showHelp("beats");
      return result;
    }

    return result;
  }

  @Override
  public void run() throws ConfigurationProblem, Bug {
    Yaml yaml = new Yaml();
    Map<String, Object> settings = null;
    try {
      settings = (Map<String, Object>) yaml.load(new FileReader(settingsPath.getValue().toFile()));
    } catch (FileNotFoundException e) {
      throw new ConfigurationProblem("The specified configuration file does not exist:" + settingsPath.getValue(), e);
    }

    Map<String, Object> flatSettings = MapUtil.flattenMap(settings);

    String[] outputs = { "logstash", "elasticsearch", "redis", "kafka" };

    for (String output : outputs) {
      if (flatSettings.keySet().stream().anyMatch(key -> key.startsWith("output." + output + ".ssl"))) {
        System.out.println("Checking " + output + " output in " + settingsPath.getValue());
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
    } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
      throw new Bug("'new KeyStoreBuilder' failed", e);
    }

    processCertificateAuthorities(flatSettings, settingsPrefix, trust);

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
    } catch (KeyManagementException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
      throw new ConfigurationProblem("Failed to build tealess context.", e);
    }

    // XXX: Check for .hosts setting.

    InetSocketAddressInput addressInput = new InetSocketAddressInput(-1); // no default port
    for (String address : ((List<String>)flatSettings.get(settingsPrefix + ".hosts"))) {
      Collection<InetAddress> addresses;
      InetSocketAddress inetAddress = addressInput.parse(address);

      String hostname = inetAddress.getHostString();

      try {
        logger.trace("Doing name resolution on {}", hostname);
        addresses = Resolver.SystemResolver.resolve(hostname);
      } catch (UnknownHostException e) {
        throw new ConfigurationProblem("Unknown host", e);
      }

      System.out.printf("%s resolved to %d addresses\n", hostname, addresses.size());
      List<SSLReport> reports = addresses.stream()
        .map(a -> checker.check(new InetSocketAddress(a, inetAddress.getPort()), hostname))
        .collect(Collectors.toList());

      System.out.println();

      List<SSLReport> successful = reports.stream().filter(SSLReport::success).collect(Collectors.toList());

      if (successful.size() > 0) {
        successful.forEach(r -> System.out.printf("Success: %s\n", r.getAddress()));
      } else {
        System.out.println("All SSL/TLS connections failed.");
      }

      Map<Class<? extends Throwable>, List<SSLReport>> failureGroups = reports.stream().filter(r -> !r.success()).collect(Collectors.groupingBy(r -> Blame.get(r.getException()).getClass()));
      for (Map.Entry<Class<? extends Throwable>, List<SSLReport>> entry : failureGroups.entrySet()) {
        Class<? extends Throwable> blame = entry.getKey();
        List<SSLReport> failures = entry.getValue();
        System.out.println();
        System.out.printf("Failure: %s\n", blame);
        for (SSLReport r : failures) {
          System.out.printf("  %s\n", r.getAddress());
        }

        SSLReportAnalyzer.analyze(blame, failures.get(0));
      }

      System.out.println();
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
        } catch (KeyStoreException e) {
          throw new Bug("Unexpected key store problem", e);
        }
      }
    }
  }
}
