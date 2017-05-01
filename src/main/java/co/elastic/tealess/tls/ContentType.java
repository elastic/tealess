package co.elastic.tealess.tls;

/**
 * Created by jls on 4/28/2017.
 */
public enum ContentType {
  ChangeCipherSpec((byte) 20),
  Alert((byte) 21),
  Handshake((byte) 22),
  ApplicationData((byte) 23);

  private byte type;

  ContentType(byte type) {
    this.type = type;
  }

  static ContentType forValue(byte value) throws InvalidValue {
    switch (value) {
      case 20:
        return ContentType.ChangeCipherSpec;
      case 21:
        return ContentType.Alert;
      case 22:
        return ContentType.Handshake;
      case 23:
        return ContentType.ApplicationData;
      default:
        throw new InvalidValue("ContentTYpe value of " + value + " is not valid.");
    }
  }
}
