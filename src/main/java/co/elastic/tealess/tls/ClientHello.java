package co.elastic.tealess.tls;

import java.util.List;

/**
 * Created by jls on 4/30/2017.
 */
public class ClientHello extends TLSHandshake {
  private final Version version;
  private final Random random;
  private final byte[] session;
  private final List<Short> cipherSuites;
  private final List<Byte> compressionMethods;
  private final byte[] extensionData;

  public ClientHello(Version version, Random random, byte[] session, List<Short> cipherSuites, List<Byte> compressionMethods, byte[] extensionData) {
    super();
    this.version = version;
    this.random = random;
    this.session = session;
    this.cipherSuites = cipherSuites;
    this.compressionMethods = compressionMethods;
    this.extensionData = extensionData;
  }

}
