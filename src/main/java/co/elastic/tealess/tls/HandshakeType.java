package co.elastic.tealess.tls;

/**
 * Created by jls on 4/28/2017.
 */
enum HandshakeType {
  HelloRequest((byte)0),
  ClientHello((byte)1),
  ServerHello((byte)2),
  Certificate((byte)11),
  ServerKeyExchange((byte)12),
  CertificateRequest((byte)13),
  ServerHelloDone((byte)14),
  CertificateVerify((byte)15),
  ClientKeyExchange((byte)16),
  Finished((byte)20);

  private byte type;

  HandshakeType(byte type) {
    this.type = type;
  }

  static HandshakeType forValue(byte value) throws InvalidValue {
    switch (value) {
      case 0:
        return HandshakeType.HelloRequest;
      case 1:
        return HandshakeType.ClientHello;
      case 2:
        return HandshakeType.ServerHello;
      case 11:
        return HandshakeType.Certificate;
      case 12:
        return HandshakeType.ServerKeyExchange;
      case 13:
        return HandshakeType.CertificateRequest;
      case 14:
        return HandshakeType.ServerHelloDone;
      case 15:
        return HandshakeType.CertificateVerify;
      case 16:
        return HandshakeType.ClientKeyExchange;
      case 20:
        return HandshakeType.Finished;
      default:
        throw new InvalidValue("HandshakeType value of " + value + " is not valid.");
    }
  }
}
