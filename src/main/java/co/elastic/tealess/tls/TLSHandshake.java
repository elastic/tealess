package co.elastic.tealess.tls;

import co.elastic.tealess.io.BufferUtil;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;


/**
 * Created by jls on 4/30/2017.
 */
public class TLSHandshake {
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
      case HelloRequest:
        //return parseHelloRequest(buffer, length);
      case ServerKeyExchange:
        //return parseServerKeyExchange(buffer, length);
      case ServerHelloDone:
        //return parseServerHelloDone(buffer, length);
      case CertificateVerify:
        //return parseCertificateVerify(buffer, length);
      case ClientKeyExchange:
        //return parseClientKeyExchange(buffer, length);
      case Finished:
        //return parseFinished(buffer, length);
      default:
        System.out.println("Parsing not implemented for " + handshakeType);
        return null;
    }

  }

  private static TLSHandshake parseCertificateRequest(ByteBuffer buffer, int length) {
    //byte[] x = new byte[length]; buffer.mark(); buffer.get(x); buffer.reset(); for (byte b : x) { System.out.printf("%02x ", b); }; System.out.println();

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

    System.out.printf("Certificates entries length: %d\n", certificatesLength);
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
    //System.out.printf("SessionID(%d, ...)\n", session.length);

    int cipherSuite = BufferUtil.readUInt16(buffer);
    byte compressionMethod = buffer.get();

    byte[] extensionData = getExtensions(buffer);

    return new ServerHello(version, random, session, cipherSuite, compressionMethod, extensionData);
  }

  private static TLSHandshake parseClientHello(ByteBuffer buffer, int length) {
    Version version = new Version(buffer.get(), buffer.get());

    // Random...
    Random random = Random.parse(buffer);

    byte[] session = getSessionID(buffer);
    //System.out.printf("SessionID(%d, ...)\n", session.length);

    int cipherSuitesLength = BufferUtil.readUInt16(buffer);
    int numCipherSuites = cipherSuitesLength / 2; // 2 bytes per cipher suite
    // XXX: Parse the cipher suites list.
    List<Short> cipherSuites = IntStream.range(0, cipherSuitesLength).boxed().map(i -> (short) BufferUtil.readUInt16(buffer)).collect(Collectors.toList());
    //System.out.printf("Cipher Suites(%d, %s)\n", cipherSuitesLength, cipherSuites);

    int compressionMethodsLength = BufferUtil.readUInt8(buffer);
    // XXX: Parse the compression methods list
    List<Byte> compressionMethods = IntStream.range(0, compressionMethodsLength).boxed().map(i -> buffer.get()).collect(Collectors.toList());
    //System.out.printf("Compression methods: %s\n", compressionMethods);

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
}
