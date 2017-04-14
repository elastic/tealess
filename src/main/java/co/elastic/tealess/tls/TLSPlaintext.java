package co.elastic.tealess.tls;

import javafx.scene.control.TextFormatter;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Created by jls on 4/13/2017.
 */
public class TLSPlaintext {
  public static TLSPlaintext parse(ByteBuffer buffer) throws InvalidValue {
    buffer.order(ByteOrder.BIG_ENDIAN);
    byte contentTypeByte = buffer.get();
    ContentType contentType = ContentType.forValue(contentTypeByte);
    byte versionMajor = buffer.get();
    byte versionMinor = buffer.get();

    int length = buffer.getShort() & 0xffff;
    // RFC: The length MUST NOT exceed 2^14 bytes
    assert(length <= 1<<14);
    assert(length > 0);

    ByteBuffer payload = buffer.duplicate();
    payload.limit(buffer.position() + length);
    buffer.position(payload.limit());
    return new TLSPlaintext(contentType, versionMajor, versionMinor, length, payload);
  }

  enum ContentType {
    ChangeCipherSpec((byte)20),
    Alert((byte)21),
    Handshake((byte)22),
    ApplicationData((byte)23);

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

  private ContentType contentType;
  private byte versionMajor;
  private byte versionMinor;
  int length; // length is uint16 in the spec, but Java has no unsigned types, so we use int.

  public TLSPlaintext(ContentType contentType, byte versionMajor, byte versionMinor, int length, ByteBuffer payload) {
    this.contentType = contentType;
    this.versionMajor = versionMajor;
    this.versionMinor = versionMinor;
    this.length = length;
  }

  public String toString() {
    return "TLSPlaintext[" + contentType + ", " + version() + ", length:" + length + "]";
  }

  public String version() {
    switch (versionMajor) {
      case 2: return "SSL 2.0?";
      case 3:
        switch(versionMinor) {
          case 0: return "SSL 3.0";
          case 1: return "TLS 1.0";
          case 2: return "TLS 1.1";
          case 3: return "TLS 1.2";
        }
      default:
        return "UNKNOWN_VERSION";
    }
  }
}
