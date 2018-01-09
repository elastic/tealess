package co.elastic.tealess.tls;


/**
 * Created by jls on 4/30/2017.
 */
public enum ClientCertificateType {
  RSASign((byte) 1),
  DSSSign((byte) 2),
  RSAFixedDH((byte) 3),
  DSSFixedDH((byte) 4),
  RSAEphemeralDHRESERVED((byte) 5),
  DSSEphemeralDHRESERVED((byte) 6),
  FortezzaDMSRESERVED((byte) 20),

  // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-2
  ECDSASign((byte) 64), // RFC 4492
  RSAFixedECDH((byte) 65), // RFC 4492
  ECDSAFixedECDH((byte) 66); // RFC 4492

  protected final byte value;

  ClientCertificateType(byte value) {
    this.value = value;
  }

  static ClientCertificateType forValue(byte value) throws InvalidValue {
    switch (value) {
      case 1:
        return RSASign;
      case 2:
        return DSSSign;
      case 3:
        return RSAFixedDH;
      case 4:
        return DSSFixedDH;
      case 5:
        return RSAEphemeralDHRESERVED;
      case 6:
        return DSSEphemeralDHRESERVED;
      case 20:
        return FortezzaDMSRESERVED;
      case 64:
        return ECDSASign;
      case 65:
        return RSAFixedECDH;
      case 66:
        return ECDSAFixedECDH;
      default:
        throw new InvalidValue("Invalid ClientCertificateType value " + value);
    }
  }
}
