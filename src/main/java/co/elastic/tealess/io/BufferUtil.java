package co.elastic.tealess.io;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/**
 * Created by jls on 4/26/2017.
 */
public class BufferUtil {
  // XXX: Keep timestamp of when each write occurs?
  public static void write(ByteBuffer source, OutputStream destination) throws IOException {
    System.err.println(source);
    int length = source.limit() - source.position();
    if (length == 0) {
      return;
    }
    byte[] data = new byte[length];
    source.get(data);

    destination.write(data);
  }

  public static long readUInt32(ByteBuffer source) {
    return (readUInt8(source) << 24) + (readUInt8(source) << 16) + (readUInt8(source) << 8) + readUInt8(source);
  }

  public static int readUInt24(ByteBuffer source) {
    return (readUInt8(source) << 16) + (readUInt8(source) << 8) + readUInt8(source);
  }

  public static int readUInt16(ByteBuffer source) {
    return (source.get() << 8) + source.get();
  }

  public static int readUInt8(ByteBuffer source) {
    return source.get() & 0xff;
  }

  public static byte[] readOpaque8(ByteBuffer source) {
    return readOpaque(source, readUInt8(source));
  }

  public static byte[] readOpaque16(ByteBuffer source) {
    return readOpaque(source, readUInt16(source));
  }

  public static byte[] readOpaque24(ByteBuffer source) {
    return readOpaque(source, readUInt24(source));
  }

  private static byte[] readOpaque(ByteBuffer source, int length) {
    if (length < 0) {
      throw new IllegalArgumentException("readOpaque length cannot be negative. got " + length);
    }
    byte[] data = new byte[length];
    source.get(data);
    return data;
  }
}
