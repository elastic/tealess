package co.elastic.tealess.tls;

/**
 * Created by jls on 4/30/2017.
 */
public class ServerHello extends TLSHandshake {
  private final Version version;
  private final Random random;
  private final byte[] session;
  private final int cipherSuite;
  private final byte compressionMethod;
  private final byte[] extensionData;

  public ServerHello(Version version, Random random, byte[] session, int cipherSuite, byte compressionMethod, byte[] extensionData) {
    super();
    this.version = version;
    this.random = random;
    this.session = session;
    this.cipherSuite = cipherSuite;
    this.compressionMethod = compressionMethod;
    this.extensionData = extensionData;
  }

  public String toString() {
    return String.format("ServerHello[%s]", version);
  }
}
