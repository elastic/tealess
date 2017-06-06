package co.elastic.tealess.tls;

import co.elastic.tealess.io.IOObserver;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;

/**
 * Created by jls on 4/13/2017.
 */
public class ObservingSSLEngine {
  private final IOObserver observer;
  private SSLEngine sslEngine;

  public ObservingSSLEngine(SSLEngine sslEngine, IOObserver observer) {
    this.sslEngine = sslEngine;
    this.observer = observer;
  }

  public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
    SSLEngineResult result = sslEngine.wrap(src, dst);
    observer.networkWrite(dst);
    return result;
  }

  public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
    SSLEngineResult result = sslEngine.unwrap(src, dst);

    // Only observe what was actually unwrapped from the source buffer.
    ByteBuffer dup = src.duplicate();
    dup.position(0);
    dup.limit(src.position());
    observer.networkRead(dup);

    return result;
  }

  public SSLEngine getSslEngine() {
    return sslEngine;
  }

  public Runnable getDelegatedTask() {
    return sslEngine.getDelegatedTask();
  }

  public SSLSession getSession() {
    return sslEngine.getSession();
  }

  public SSLSession getHandshakeSession() {
    return sslEngine.getHandshakeSession();
  }

  public void beginHandshake() throws SSLException {
    sslEngine.beginHandshake();
  }

  public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
    return sslEngine.getHandshakeStatus();
  }

  public void setUseClientMode(boolean b) {
    sslEngine.setUseClientMode((b));
  }


}
