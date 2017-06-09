package co.elastic.tealess.io;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.ByteBuffer;

/**
 * Created by jls on 5/1/2017.
 */
public class IOLog {
  public ByteBuffer getBuffer() {
    return buffer;
  }

  public Operation getOperation() {
    return operation;
  }

  public enum Operation {
    Read, Write
  }

  private static final Logger logger = LogManager.getLogger();

  private long timestamp = System.nanoTime();
  private Operation operation;
  private ByteBuffer buffer;

  private IOLog(Operation operation, ByteBuffer buffer) {
    this.operation = operation;
    this.buffer = buffer;
    logger.trace("IOLog {} of {}", operation, buffer);
  }

  public String toString() {
    return String.format("%s of %d bytes", operation, buffer.limit());
  }

  public static IOLog newWrite(ByteBuffer buffer) {
    return new IOLog(Operation.Write, buffer);
  }

  public static IOLog newRead(ByteBuffer buffer) {
    return new IOLog(Operation.Read, buffer);
  }
}
