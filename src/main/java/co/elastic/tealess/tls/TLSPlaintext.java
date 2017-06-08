package co.elastic.tealess.tls;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Created by jls on 4/13/2017.
 */
public class TLSPlaintext {
  private final ByteBuffer payload;

  private ContentType contentType;
  private Version version;
  int length; // length is uint16 in the spec, but Java has no unsigned types, so we use int.

  public static TLSPlaintext parse(ByteBuffer buffer) throws InvalidValue {
    buffer.order(ByteOrder.BIG_ENDIAN);
    byte contentTypeByte = buffer.get();
    ContentType contentType = ContentType.forValue(contentTypeByte);
    Version version = new Version(buffer.get(), buffer.get());

    int length = buffer.getShort() & 0xffff;
    // RFC: The length MUST NOT exceed 2^14 bytes
    assert (length <= 1 << 14);
    assert (length > 0);

    ByteBuffer payload = buffer.duplicate();
    payload.limit(buffer.position() + length);
    buffer.position(payload.limit());
    return new TLSPlaintext(contentType, version, length, payload);
  }


  public TLSPlaintext(ContentType contentType, Version version, int length, ByteBuffer payload) {
    this.contentType = contentType;
    this.version = version;
    this.length = length;
    this.payload = payload;
  }

  public String toString() {
    return "TLSPlaintext[" + contentType + ", " + version + ", length:" + length + "]";
  }

  public ContentType getContentType() {
    return contentType;
  }

  public ByteBuffer getPayload() {
    return payload;
  }
}
