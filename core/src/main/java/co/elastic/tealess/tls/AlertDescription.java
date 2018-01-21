package co.elastic.tealess.tls;

public enum AlertDescription {
  CloseNotify((byte) 0),
  UnexpectedMessage((byte) 10),
  BadRecordMac((byte) 20),
  DecryptionFailedRESERVED((byte) 21),
  RecordOverflow((byte) 22),
  DecompressionFailure((byte) 30),
  HandshakeFailure((byte) 40),
  NoCertificateRESERVED((byte) 41),
  BadCertificate((byte) 42),
  UnsupportedCertificate((byte) 43),
  CertificateRevoked((byte) 44),
  CertificateExpired((byte) 45),
  CertificateUnknown((byte) 46),
  IllegalParameter((byte) 47),
  UnknownCa((byte) 48),
  AccessDenied((byte) 49),
  DecodeError((byte) 50),
  DecryptError((byte) 51),
  ExportRestrictionRESERVED((byte) 60),
  ProtocolVersion((byte) 70),

  InsufficientSecurity((byte) 71),
  InternalError((byte) 80),
  UserCanceled((byte) 90),
  NoRenegotiation((byte) 100),
  UnsupportedExtension((byte) 110);

  private final byte value;

  AlertDescription(byte value) {
    this.value = value;
  }

  static AlertDescription forValue(byte value) throws InvalidValue {
    for (AlertDescription description : AlertDescription.values()) {
      if (description.value == value) {
        return description;
      }
    }

    throw new InvalidValue(String.format("Invalid AlertDescription value %d", value));
  }
}
