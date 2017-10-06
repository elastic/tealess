package co.elastic.tealess.tls;

import java.nio.ByteBuffer;

/**
 * Created by jls on 4/14/2017.
 */
public class TLSDecoder {
  public static TLSPlaintext decode(ByteBuffer buffer) throws InvalidValue {
    // Per RFC 5246, the top level record is TLSPlaintext.
    return TLSPlaintext.parse(buffer);
  }

  public static TLSHandshake decodeHandshake(ByteBuffer buffer) throws InvalidValue {
    return TLSHandshake.parse(buffer);
  }

  public static Alert decodeAlert(ByteBuffer buffer) throws InvalidValue {
      return new Alert(AlertLevel.forValue(buffer.get()), AlertDescription.forValue(buffer.get()));
  }
}
