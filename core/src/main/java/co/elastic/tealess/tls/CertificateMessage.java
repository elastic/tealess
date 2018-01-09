package co.elastic.tealess.tls;

import java.security.cert.Certificate;
import java.util.List;

/**
 * Created by jls on 4/30/2017.
 */
public class CertificateMessage extends TLSHandshake {
  private final List<Certificate> chain;

  public CertificateMessage(List<Certificate> chain) {
    super();
    this.chain = chain;
  }

  public List<Certificate> getChain() {
    return chain;
  }

  public String toString() {
    return String.format("%s[%d certificates]", getClass().getSimpleName(), chain.size());
  }
}
