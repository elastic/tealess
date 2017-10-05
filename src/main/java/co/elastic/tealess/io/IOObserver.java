package co.elastic.tealess.io;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;

/**
 * Created by jls on 4/13/2017.
 */
@Deprecated
public class IOObserver {
  private static final Logger logger = LogManager.getLogger();

  private final List<IOLog> ioLogs = new LinkedList<>();

  private final ByteArrayOutputStream networkIn = new ByteArrayOutputStream();
  private final ByteArrayOutputStream networkOut = new ByteArrayOutputStream();

  private static void writeSilent(ByteBuffer buffer, ByteArrayOutputStream out) {
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
    ioLogs.add(IOLog.newRead(buffer.duplicate()));
    logger.trace("networkRead({}) now {}", buffer, networkIn.size());
  }

  public ByteBuffer getInputData() {
    return ByteBuffer.wrap(networkIn.toByteArray());
  }

  public void networkWrite(ByteBuffer buffer) {
    ByteBuffer dup = buffer.duplicate();
    dup.flip();
    ioLogs.add(IOLog.newWrite(dup.duplicate()));
    writeSilent(dup, networkOut);
    logger.trace("networkWrite({}) now {}", dup, networkOut.size());
  }

  public ByteBuffer getOutputData() {
    return ByteBuffer.wrap(networkOut.toByteArray());
  }

  public List<IOLog> getLog() {
    return ioLogs;
  }
}
