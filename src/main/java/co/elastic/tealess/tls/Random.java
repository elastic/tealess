package co.elastic.tealess.tls;

import co.elastic.tealess.io.BufferUtil;

import java.nio.ByteBuffer;

/**
 * Created by jls on 4/30/2017.
 */
public class Random {
  private final long time;
  private final byte[] random;

  public Random(long time, byte[] random) {
    this.time = time;
    this.random = random;
  }

  public static Random parse(ByteBuffer source) {
    long time = BufferUtil.readUInt32(source);
    byte[] random = new byte[28];
    source.get(random);
    return new Random(time, random);
  }
}
