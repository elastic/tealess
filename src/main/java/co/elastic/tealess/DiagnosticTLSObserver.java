package co.elastic.tealess;

import co.elastic.Blame;
import co.elastic.tealess.io.SSLSocketProxy;
import co.elastic.tealess.io.SocketProxy;
import co.elastic.tealess.io.Transaction;
import co.elastic.tealess.tls.CertificateMessage;
import co.elastic.tealess.tls.InvalidValue;
import co.elastic.tealess.tls.TLSDecoder;
import co.elastic.tealess.tls.TLSHandshake;
import co.elastic.tealess.tls.TLSPlaintext;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
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
//    private final List<Transaction<?>> log = new LinkedList<Transaction<?>>() {
//        public boolean add(Transaction<?> e) {
//            System.out.println(e);
//            return super.add(e);
//        }
//    };

    private void recordInput(int length) {
        log.add(Transaction.create(Transaction.Operation.Input, length));
    }

    private void recordOutput(int length) {
        log.add(Transaction.create(Transaction.Operation.Output, length));
    }

    private void recordException(Throwable cause) {
        log.add(Transaction.create(Transaction.Operation.Exception, cause));
    }

    private void exception(Throwable cause) throws IOException {
        recordException(cause);
        inputBuffer.flip();
        outputBuffer.flip();
        diagnoseException(cause);
    }

    private void diagnoseException(Throwable cause) throws IOException {
        StringBuilder report = new StringBuilder();

        Throwable blame = Blame.get(cause);
        if (blame instanceof sun.security.provider.certpath.SunCertPathBuilderException) {
            report.append("The remote server provided an unknown/untrusted certificate chain, so the connection terminated by the client.\n");
            readLog(report);
            Throwable x = cause;
            do {
                //System.out.printf("Cause: %s - %s\n", x.getClass(), x);
                x = x.getCause();
            } while (x != null);

            SSLHandshakeException diagnosis = new SSLHandshakeException(report.toString());
            diagnosis.initCause(cause);
            throw diagnosis;
            //throw new SSLHandshakeException(report.toString(), cause);
        }

    }

    private void readLog(StringBuilder builder) {

        builder.append("Here is a network log before the failure:\n");
        int inputBytes = 0, outputBytes = 0;
        for (Transaction<?> transaction : log) {
            int length;
            switch(transaction.op) {
                case Input:
                    length = ((Transaction<Integer>) transaction).value;
                    if (inputBuffer.position() == 0 || inputBuffer.position() < inputBytes) {
                        builder.append("INPUT: ");
                        decodeBuffer(inputBuffer, length, builder);
                    }
                    inputBytes += length;
                    break;
                case Output:
                    length = ((Transaction<Integer>) transaction).value;
                    if (outputBuffer.position() == 0 || outputBuffer.position() < outputBytes) {
                        builder.append("OUTPUT: ");
                        decodeBuffer(outputBuffer, length, builder);
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

    private static void decodeBuffer(ByteBuffer buffer, int length, StringBuilder builder) {
        int initial = buffer.position();
        length = Math.min(initial + length, buffer.limit()) - initial;
        while (buffer.position() < initial + length) {
            final TLSPlaintext plaintext;
            try {
                plaintext = TLSPlaintext.parse(buffer);
            } catch (InvalidValue e) {
                builder.append(String.format("Invalid value decoding handshake: %s\n", e));
                return;
            }
            switch (plaintext.getContentType()) {
                case ChangeCipherSpec:
                case Alert:
                case ApplicationData:
                    builder.append(String.format("%s\n", plaintext.getContentType()));
                    break;
                case Handshake:
                    final TLSHandshake handshake;
                    try {
                        handshake = TLSDecoder.decodeHandshake(plaintext.getPayload());
                    } catch (InvalidValue e) {
                        builder.append(String.format("Invalid value decoding handshake: %s\n", e));
                        return;
                    }
                    builder.append(String.format("Handshake message: %s\n", handshake));
                    if (handshake instanceof CertificateMessage) {
                        CertificateMessage message = (CertificateMessage) handshake;
                        int i = 0;
                        for (Certificate certificate : message.getChain()) {
                            X509Certificate x509 = (X509Certificate) certificate;
                            builder.append(String.format("%d: %s\n", i, x509.getSubjectX500Principal()));
                            try {
                                if (x509.getSubjectAlternativeNames() != null) {
                                    for (List<?> x : x509.getSubjectAlternativeNames()) {
                                        int type = (Integer) x.get(0);
                                        String value = (String) x.get(1);
                                        switch (type) {
                                            case 2: // dNSName per RFC5280 4.2.1.6
                                                builder.append(String.format("  subjectAlt: DNS:%s\n", value));
                                                break;
                                            case 7: // iPAddress per RFC5280 4.2.1.6
                                                builder.append(String.format("  subjectAlt: IP:%s\n", value));
                                                break;
                                            default:
                                                builder.append(String.format("  subjectAlt: [%d]:%s\n", type, value));
                                                break;
                                        }
                                    }
                                }
                            } catch (CertificateParsingException e) {
                                builder.append(String.format("  Certificat parsing failure: %s\n", e));
                            }
                            i++;
                        } // for : message.getChain()
                    }
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
        return new SocketProxy(socket, this::read, this::write, this::exception);
    }

    @Override
    public SSLSocket observeIO(SSLSocket socket) {
        return new SSLSocketProxy(socket, this::read, this::write, this::exception);
    }

    @Override
    public Socket observeExceptions(Socket socket) {
        return new SocketProxy(socket, null, null, this::exception);
    }

    @Override
    public SSLSocket observeExceptions(SSLSocket socket) {
        return new SSLSocketProxy(socket, null, null, this::exception);
    }
}
