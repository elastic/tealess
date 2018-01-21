package co.elastic.tealess.io;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Created by jls on 4/26/2017.
 */
class BufferUtilTest {
  private final ByteBuffer buffer = ByteBuffer.allocate(1024);
  private final ByteArrayOutputStream output = new ByteArrayOutputStream();

  @Test
  void testWrite() throws IOException {
    String input = "hello world";
    buffer.put(input.getBytes());
    buffer.flip();

    BufferUtil.write(buffer, output);

    byte[] result = output.toByteArray();
    assertEquals(input, new String(result));
  }

}