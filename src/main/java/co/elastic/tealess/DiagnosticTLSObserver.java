package co.elastic.tealess;

import co.elastic.tealess.io.SocketWrapper;
import co.elastic.tealess.io.Transaction;
import co.elastic.tealess.tls.CertificateMessage;
import co.elastic.tealess.tls.InvalidValue;
import co.elastic.tealess.tls.TLSDecoder;
import co.elastic.tealess.tls.TLSHandshake;
import co.elastic.tealess.tls.TLSPlaintext;

import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

public class DiagnosticTLSObserver implements TLSObserver {
    private final ByteBuffer inputBuffer = ByteBuffer.allocate(16384);
    private final ByteBuffer outputBuffer = ByteBuffer.allocate(16384);

    private final List<Transaction<?>> log = new LinkedList<>();

    private void recordInput(int length) {
        log.add(Transaction.create(Transaction.Operation.Input, length));
    }

    private void recordOutput(int length) {
        log.add(Transaction.create(Transaction.Operation.Output, length));
    }

    private void recordException(Throwable cause) {
        log.add(Transaction.create(Transaction.Operation.Exception, cause));
    }

    private void exception(Throwable cause) {
        recordException(cause);
        inputBuffer.flip();
        outputBuffer.flip();
        try {
            diagnoseException(cause, inputBuffer);
        } catch (InvalidValue invalidValue) {
            invalidValue.printStackTrace();
        }
    }

    private void diagnoseException(Throwable cause, ByteBuffer inputBuffer) throws InvalidValue {
        System.out.println("Exception: " + cause.getClass() + ":" + cause);

        int inputBytes = 0, outputBytes = 0;

        for (Transaction<?> transaction : log) {
            int length;
            switch(transaction.op) {
                case Input:
                    length = ((Transaction<Integer>) transaction).value;
                    if (inputBuffer.position() < inputBytes) {
                        System.out.println("<<< INPUT");
                        decodeBuffer(inputBuffer, length);
                    }
                    inputBytes += length;
                    break;
                case Output:
                    length = ((Transaction<Integer>) transaction).value;
                    if (outputBuffer.position() < outputBytes) {
                        System.out.println(">>> OUTPUT");
                        decodeBuffer(outputBuffer, length);
                    }
                    outputBytes += length;
                    break;
                case Exception:
                    //Throwable cause = ((Transaction<Throwable>)transaction).value;
                    //System.out.println("Terminating exception: " + cause.getClass() + ": " + cause);
                    break;
            }
        }

    }

    private static void decodeBuffer(ByteBuffer buffer, int length) throws InvalidValue {
        int initial = buffer.position();
        length = Math.min(initial + length, buffer.limit()) - initial;
        while (buffer.position() < initial + length) {
            //System.out.printf("pos:%d, limit:%d -- target:%d", buffer.position(), buffer.limit(), (initial + length));
            TLSPlaintext plaintext = TLSPlaintext.parse(buffer);
            System.out.println(plaintext);
            switch (plaintext.getContentType()) {
                case ChangeCipherSpec:
                    System.out.println(plaintext.getContentType());
                    break;
                case Alert:
                    System.out.println(plaintext.getContentType());
                    break;
                case Handshake:
                    TLSHandshake handshake = TLSDecoder.decodeHandshake(plaintext.getPayload());
                    System.out.println("Handshake message: " + handshake);
                    if (handshake instanceof CertificateMessage) {
                        CertificateMessage message = (CertificateMessage) handshake;
                        int i = 0;
                        for (Certificate certificate : message.getChain()) {
                            X509Certificate x509 = (X509Certificate) certificate;
                            System.out.printf("%d: %s\n", i, x509.getSubjectX500Principal());
                            try {
                                if (x509.getSubjectAlternativeNames() != null) {
                                    for (List<?> x : x509.getSubjectAlternativeNames()) {
                                        int type = (Integer) x.get(0);
                                        String value = (String) x.get(1);
                                        switch (type) {
                                            case 2: // dNSName per RFC5280 4.2.1.6
                                                System.out.printf("  subjectAlt: DNS:%s\n", value);
                                                break;
                                            case 7: // iPAddress per RFC5280 4.2.1.6
                                                System.out.printf("  subjectAlt: IP:%s\n", value);
                                                break;
                                            default:
                                                System.out.printf("  subjectAlt: [%d]:%s\n", type, value);
                                                break;
                                        }
                                    }
                                }
                            } catch (CertificateParsingException e) {
                                e.printStackTrace();
                            }
                            i++;

                        }
                    }
                    break;
                case ApplicationData:
                    System.out.println(plaintext.getContentType());
                    break;
            }
        }
    }

    private void read(byte[] b, int off, int len, int ret) {
        recordInput(ret);
        if (ret >= 0) {
            inputBuffer.put(b, off, ret); // ret is number of bytes actually written
        }

    }

    private void write(byte[] b, int off, int len) {
        recordOutput(len);
        outputBuffer.put(b, off, len);

    }

    @Override
    public Socket observeIO(Socket socket) {
        return new SocketWrapper(socket, this::read, this::write, this::exception);
    }

    @Override
    public Socket observeExceptions(Socket socket) {
        return new SocketWrapper(socket, null, null, this::exception);
    }

}
