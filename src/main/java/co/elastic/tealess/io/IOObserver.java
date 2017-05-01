package co.elastic.tealess.io;

import co.elastic.tealess.io.BufferUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/**
 * Created by jls on 4/13/2017.
 */
public class IOObserver {
  // XXX: Add transaction with time as counter so we can replay things.

  private ByteArrayOutputStream networkIn = new ByteArrayOutputStream();
  private ByteArrayOutputStream networkOut = new ByteArrayOutputStream();

  static void writeSilent(ByteBuffer buffer, ByteArrayOutputStream out) {
    try {
      BufferUtil.write(buffer, out);
    } catch (IOException e) {
      // OutputStream.write's signature includes `throws IOException`.
      // However, reading the ByteArrayOutputStream code in the JDK,
      // this class will never actually throw an IOException...
      // So we do an empty catch here to silence the compiler.
    }
  }

  public void networkRead(ByteBuffer buffer) {
    writeSilent(buffer.duplicate(), networkIn);
    System.out.printf("networkRead(" + buffer + ") now %s\n", networkIn.size());
  }

  public ByteBuffer getInputData() {
    return ByteBuffer.wrap(networkIn.toByteArray());
  }

  public void networkWrite(ByteBuffer buffer) {
    ByteBuffer dup = buffer.duplicate();
    dup.flip();
    writeSilent(dup, networkOut);
    System.out.printf("networkWrite(" + dup + ") now %s\n", networkOut.size());
  }

  public ByteBuffer getOutputData() {
    return ByteBuffer.wrap(networkOut.toByteArray());
  }

}
