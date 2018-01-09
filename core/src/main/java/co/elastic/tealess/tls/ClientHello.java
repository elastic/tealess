package co.elastic.tealess.tls;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Created by jls on 4/30/2017.
 */
public class ClientHello extends TLSHandshake {
  private final Version version;
  private final Random random;
  private final byte[] session;
  private final List<CipherSuite> cipherSuites;
  private final List<Byte> compressionMethods;
  private final byte[] extensionData;

    public Version getVersion() {
        return version;
    }

    public Random getRandom() {
        return random;
    }

    public byte[] getSession() {
        return session;
    }

    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public List<Byte> getCompressionMethods() {
        return compressionMethods;
    }

    public byte[] getExtensionData() {
        return extensionData;
    }

    public ClientHello(Version version, Random random, byte[] session, List<CipherSuite> cipherSuites, List<Byte> compressionMethods, byte[] extensionData) {
    super();
    this.version = version;
    this.random = random;
    this.session = session;
    this.cipherSuites = cipherSuites;
    this.compressionMethods = compressionMethods;
    this.extensionData = extensionData;
  }

  public String toString() {
    return String.format("%s[version: %s, %d cipher suites; suites: %s]", getClass().getSimpleName(), version, cipherSuites.size(), cipherSuites.stream().map(CipherSuite::toString).collect(Collectors.joining(", ")));
  }

}
