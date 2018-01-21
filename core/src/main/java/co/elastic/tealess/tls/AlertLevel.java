package co.elastic.tealess.tls;

public enum AlertLevel {
  Warning((byte) 0),
  Fatal((byte) 2);

  private final byte value;

  AlertLevel(byte value) {
    this.value = value;
  }

  static AlertLevel forValue(byte value) throws InvalidValue {
    switch (value) {
      case 0:
        return Warning;
      case 2:
        return Fatal;
      default:
        throw new InvalidValue("Unknown AlertLevel value " + value);
    }
  }
}
