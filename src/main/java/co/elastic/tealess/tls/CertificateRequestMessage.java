package co.elastic.tealess.tls;

import java.util.List;

/**
 * Created by jls on 4/30/2017.
 */
public class CertificateRequestMessage extends TLSHandshake {
  private final List<ClientCertificateType> clientCertificateTypes;
  private final List<byte[]> certificateAuthorities;

  public CertificateRequestMessage(List<ClientCertificateType> clientCertificateTypes, List<byte[]> certificateAuthorities) {
    super();
    this.clientCertificateTypes = clientCertificateTypes;
    this.certificateAuthorities = certificateAuthorities;
  }

  public String toString() {
    return String.format("%s(certificate types: %s)", getClass().getSimpleName(), clientCertificateTypes);
  }
}
