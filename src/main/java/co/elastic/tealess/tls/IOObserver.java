package co.elastic.tealess.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Created by jls on 4/13/2017.
 */
public class IOObserver {
  private class ByteArrayOutputStream2 extends ByteArrayOutputStream {
    // XXX: Keep timestamp of when each write occurs?

    void write(ByteBuffer buffer){
      int length = buffer.limit() - buffer.position();
      if (length == 0) {
        return;
      }
      byte[] data = new byte[length];
      buffer.get(data);

      // ByteArrayOutputStream will never throw IOException on a write, so let's satisfy the compiler and silence it.
      try {
        write(data);
      } catch (IOException e) {
        System.out.println("ByteArrayOutputStream.write failed (bug?).");
        e.printStackTrace();
      }
    }
  }

  ByteArrayOutputStream2 networkIn = new ByteArrayOutputStream2();
  ByteArrayOutputStream2 networkOut = new ByteArrayOutputStream2();

  public void networkRead(ByteBuffer buffer) {
    System.out.println("networkRead(" + buffer + ")");
    networkIn.write(buffer.duplicate());
  }

  public ByteBuffer getInputData() {
    return ByteBuffer.wrap(networkIn.toByteArray());
  }

  public void networkWrite(ByteBuffer buffer) {
    System.out.println("networkWrite(" + buffer + ")");
    networkOut.write(buffer.duplicate());
  }

  public ByteBuffer getOutputData() {
    return ByteBuffer.wrap(networkOut.toByteArray());
  }

}
