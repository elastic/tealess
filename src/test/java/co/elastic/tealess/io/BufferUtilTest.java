package co.elastic.tealess.io;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import static org.junit.Assert.assertEquals;

/**
 * Created by jls on 4/26/2017.
 */
public class BufferUtilTest {
    public final ByteBuffer buffer = ByteBuffer.allocate(1024);
    private final ByteArrayOutputStream output = new ByteArrayOutputStream();

  @Test
  public void testWrite() throws IOException {
    String input = "hello world";
    buffer.put(input.getBytes());
    buffer.flip();

    BufferUtil.write(buffer, output);

    byte[] result = output.toByteArray();
    assertEquals(input, new String(result));
  }

}