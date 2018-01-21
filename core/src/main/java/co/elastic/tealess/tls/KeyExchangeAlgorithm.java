package co.elastic.tealess.tls;

public enum KeyExchangeAlgorithm {
  DHE_DSS((byte) 0),
  DHE_RSA((byte) 1),
  DH_ANON((byte) 2),
  RSA((byte) 3),
  DH_DSS((byte) 4),
  DH_RSA((byte) 5);

  private final byte value;

  KeyExchangeAlgorithm(byte value) {
    this.value = value;
  }

  static KeyExchangeAlgorithm forValue(byte value) throws InvalidValue {
    switch (value) {
      case 0:
        return DHE_DSS;
      case 1:
        return DHE_RSA;
      case 2:
        return DH_ANON;
      case 3:
        return RSA;
      case 4:
        return DH_DSS;
      case 5:
        return DH_RSA;
      default:
        throw new InvalidValue("Invalid or unsuppoorted KeyExchangeAlgorithm value " + value);
    }
  }
}
