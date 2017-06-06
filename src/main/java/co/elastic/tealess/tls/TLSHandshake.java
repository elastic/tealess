package co.elastic.tealess.tls;

import co.elastic.tealess.io.BufferUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;


public class TLSHandshake {
  private static final Logger logger = LogManager.getLogger();

  public static TLSHandshake parse(ByteBuffer buffer) throws InvalidValue {
    //byte[] x = new byte[100]; buffer.mark(); buffer.get(x); buffer.reset(); for (byte b : x) { System.out.printf("%02x ", b); }; System.out.println();
    HandshakeType handshakeType = HandshakeType.forValue(buffer.get());
    int length = BufferUtil.readUInt24(buffer);

    // XXX: Assert that we have enough data in the buffer?

    switch (handshakeType) {
      case ClientHello:
        return parseClientHello(buffer, length);
      case ServerHello:
        return parseServerHello(buffer, length);
      case Certificate:
        return parseCertificate(buffer, length);
      case CertificateRequest:
        return parseCertificateRequest(buffer, length);
      case ServerHelloDone:
        return parseServerHelloDone(buffer, length);
      case ServerKeyExchange:
        return parseServerKeyExchange(buffer, length);
      case HelloRequest:
        return parseHelloRequest(buffer, length);
      case ClientKeyExchange:
        return parseClientKeyExchange(buffer, length);
      case CertificateVerify:
        //return parseCertificateVerify(buffer, length);
      case Finished:
        //return parseFinished(buffer, length);
      default:
        logger.warn("Parsing not implemented for " + handshakeType);
        return null;
    }

  }

  private static TLSHandshake parseClientKeyExchange(ByteBuffer buffer, int length) {
    System.out.println("ClientKeyExchange -- ");
    byte[] x = new byte[buffer.limit() - buffer.position()]; buffer.mark(); buffer.get(x); buffer.reset(); for (byte b : x) { System.out.printf("%02x ", b); }; System.out.println();
    System.out.println();
    byte[] kex = new byte[length];
    buffer.get(kex);
    return new ClientKeyExchange(kex);
  }

  private static TLSHandshake parseHelloRequest(ByteBuffer buffer, int length) {
    return new HelloRequest();
  }

  private static TLSHandshake parseServerKeyExchange(ByteBuffer buffer, int length) {
    return new ServerKeyExchange();
  }

  private static TLSHandshake parseServerHelloDone(ByteBuffer buffer, int length) {
    // This message has nothing in it.
    return new ServerHelloDone();
  }

  private static TLSHandshake parseCertificateRequest(ByteBuffer buffer, int length) {

    int typesLength = BufferUtil.readUInt8(buffer);
    List<ClientCertificateType> certificateTypes = new LinkedList<>();
    for (int i = 0; i < typesLength; i++) {
      try {
        certificateTypes.add(ClientCertificateType.forValue(buffer.get()));
        } catch (InvalidValue invalidValue) {
        invalidValue.printStackTrace();
        return null;
      }
    }

    byte[] signatureAndHashAlgorithm = BufferUtil.readOpaque16(buffer);

    List<byte[]> certificateAuthorities = new LinkedList<>();

    int certificateAuthoritiesLength = BufferUtil.readUInt16(buffer);
    while (certificateAuthoritiesLength > 0) {
      final byte[] distinguishedName = BufferUtil.readOpaque16(buffer);
      certificateAuthorities.add(distinguishedName);
      certificateAuthoritiesLength -= distinguishedName.length + 3;
    }

    return new CertificateRequestMessage(certificateTypes, certificateAuthorities);
  }

  private static TLSHandshake parseCertificate(ByteBuffer buffer, int length) {
    CertificateFactory certificateFactory = null;
    try {
      certificateFactory = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      e.printStackTrace();
      return null;
    }

    //       opaque ASN.1Cert<1..2^24-1>;
    List<Certificate> chain = new LinkedList<>();

    int certificatesLength = BufferUtil.readUInt24(buffer);

    while (certificatesLength > 0) {
      //       struct {
      //         ASN.1Cert certificate_list<0..2^24-1>;
      //       } Certificate;
      byte[] certificateEntry = BufferUtil.readOpaque24(buffer);
      certificatesLength -= certificateEntry.length + 3;

      // XXX: Can certificateFactory.generateCertificates work on this?
      try {
        chain.add(certificateFactory.generateCertificate(new ByteArrayInputStream(certificateEntry)));
      } catch (CertificateException e) {
        e.printStackTrace();
        return null;
      }
    }

    return new CertificateMessage(chain);
  }

  private static TLSHandshake parseServerHello(ByteBuffer buffer, int length) {
    Version version = new Version(buffer.get(), buffer.get());
    Random random = Random.parse(buffer);
    byte[] session = getSessionID(buffer);

    CipherSuite cipherSuite;
    try {
      cipherSuite = CipherSuite.forValue(buffer.get(), buffer.get());
    } catch (InvalidValue invalidValue) {
      invalidValue.printStackTrace();
      return null;
    }

    byte compressionMethod = buffer.get();

    byte[] extensionData = getExtensions(buffer);

    return new ServerHello(version, random, session, cipherSuite, compressionMethod, extensionData);
  }

  private static TLSHandshake parseClientHello(ByteBuffer buffer, int length) {
    Version version = new Version(buffer.get(), buffer.get());

    // Random...
    Random random = Random.parse(buffer);

    byte[] session = getSessionID(buffer);

    int cipherSuitesLength = BufferUtil.readUInt16(buffer);
    int numCipherSuites = cipherSuitesLength / 2; // 2 bytes per cipher suite
    List<CipherSuite> cipherSuites = new LinkedList<>();
    // XXX: Parse the cipher suites list.)
    for (int i = 0; i < numCipherSuites; i++) {
      try {
        CipherSuite cipherSuite = CipherSuite.forValue(buffer.get(), buffer.get());
        cipherSuites.add(cipherSuite);
      } catch (InvalidValue invalidValue) {
        invalidValue.printStackTrace();
        return null;
      }
    }

    int compressionMethodsLength = BufferUtil.readUInt8(buffer);
    // XXX: Parse the compression methods list
    List<Byte> compressionMethods = IntStream.range(0, compressionMethodsLength).boxed().map(i -> buffer.get()).collect(Collectors.toList());

    byte[] extensionData = getExtensions(buffer);

    return new ClientHello(version, random, session, cipherSuites, compressionMethods, extensionData);
  }

  private static byte[] getSessionID(ByteBuffer buffer) {
    int sessionLength = buffer.get();
    byte[] session = new byte[sessionLength];
    buffer.get(session);
    return session;
  }

  private static byte[] getExtensions(ByteBuffer buffer) {
    /* From RFC 5246 section 7.4.1.2:
     *   > The presence of extensions can be detected by determining whether there
     *   > are bytes following the compression_methods at the end of the ClientHello.
     */
    int extensionsLength = 0;

    // Per RFC, older clients may not support extensions and thus won't send any.
    if (buffer.hasRemaining()) {
      extensionsLength = buffer.get();
    }
    byte[] extensionData = new byte[extensionsLength];
    // XXX: Parse the extension data
    buffer.get(extensionData);
    return extensionData;
  }

  public String toString() {
    return getClass().getSimpleName();
  }
}
