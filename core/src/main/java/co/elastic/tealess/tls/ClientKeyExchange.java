package co.elastic.tealess.tls;

/**
 * Created by jls on 5/1/2017.
 */
public class ClientKeyExchange extends TLSHandshake {
    private final byte[] kex;

  public ClientKeyExchange(byte[] kex) {
    super();
    this.kex = kex;
  }
}
