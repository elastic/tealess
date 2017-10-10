package co.elastic.tealess;

import co.elastic.Blame;
import co.elastic.tealess.io.ObservableSSLSocket;
import co.elastic.tealess.io.ObservableSocket;
import co.elastic.tealess.io.Transaction;
import co.elastic.tealess.tls.Alert;
import co.elastic.tealess.tls.CertificateMessage;
import co.elastic.tealess.tls.InvalidValue;
import co.elastic.tealess.tls.TLSDecoder;
import co.elastic.tealess.tls.TLSHandshake;
import co.elastic.tealess.tls.TLSPlaintext;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.lang.reflect.InvocationTargetException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

public class DiagnosticTLSObserver implements TLSObserver {
    private final ByteBuffer inputBuffer = ByteBuffer.allocate(16384);
    private final ByteBuffer outputBuffer = ByteBuffer.allocate(16384);
    private final List<Transaction<?>> log = new LinkedList<>();
    private final TrustManager[] trustManagers;

    public DiagnosticTLSObserver(TrustManager[] trustManagers) {
        this.trustManagers = trustManagers;
    }

    private void recordInput(int length) {
        log.add(Transaction.create(Transaction.Operation.Input, length));
    }

    private void recordOutput(int length) {
        log.add(Transaction.create(Transaction.Operation.Output, length));
    }

    private void recordException(Throwable cause) {
        log.add(Transaction.create(Transaction.Operation.Exception, cause));
    }

    private void exception(Throwable cause) throws SSLException {
        recordException(cause);
        inputBuffer.flip();
        outputBuffer.flip();
        diagnoseException(log, inputBuffer, outputBuffer, cause, trustManagers);
    }

    public static void diagnoseException(List<Transaction<?>> log, ByteBuffer inputBuffer, ByteBuffer outputBuffer, Throwable cause, TrustManager[] trustManagers) throws SSLException {
        StringBuilder report = new StringBuilder();
        // xxx: find the correct one.
        // XXX: Have a way for the TrustManager to tell the socket (or this observer?) about itself so that we don't have
        // xxx: to do this lookup (which fails if using the default trust manager on the system).
        X509ExtendedTrustManager trustManager = (X509ExtendedTrustManager) trustManagers[0];

        Throwable blame = Blame.get(cause);

        if (blame instanceof sun.security.provider.certpath.SunCertPathBuilderException) {
            X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
            report.append("The remote server provided an unknown/untrusted certificate chain, so the connection terminated by the client.\n");
            report.append(String.format("The local client has %d certificates in the trust store.\n", acceptedIssuers.length));
//            This is commented out because when using the system-default trust store, there are 100+ trusted certs and the output is *really* long.
//            XXX: Long term, figure out how to just say "The local client is using the default system trust store" instead, then uncomment this for only custom stores.
//            for (int i = 0; i < acceptedIssuers.length; i++)  {
//                try {
//                    Collection<List<?>> subjectAlternativeNames = acceptedIssuers[i].getSubjectAlternativeNames();
//                    if (subjectAlternativeNames == null) {
//                        report.append(String.format("%d: %s (no subject alternatives))\n", i, acceptedIssuers[i].getSubjectX500Principal()));
//                    } else {
//                        report.append(String.format("%d: %s (%d subject alternatives)\n", i, acceptedIssuers[i].getSubjectX500Principal(), acceptedIssuers[i].getSubjectAlternativeNames().size()));
//                        for (List<?> x : subjectAlternativeNames) {
//                            int type = (Integer) x.get(0);
//                            String value = (String) x.get(1);
//                            switch (type) {
//                                case 2: // dNSName per RFC5280 4.2.1.6
//                                    report.append(String.format("  subjectAlt: DNS:%s\n", value));
//                                    break;
//                                case 7: // iPAddress per RFC5280 4.2.1.6
//                                    report.append(String.format("  subjectAlt: IP:%s\n", value));
//                                    break;
//                                default:
//                                    report.append(String.format("  subjectAlt: [%d]:%s\n", type, value));
//                                    break;
//                            }
//                        }
//                    }
//                } catch (CertificateParsingException e) {
//                    e.printStackTrace();
//                }
//            }

            readLog(report, log, inputBuffer, outputBuffer);
            SSLHandshakeException diagnosis = new SSLHandshakeException(report.toString());
            diagnosis.initCause(cause);
            throw diagnosis;
        } else if (blame instanceof SSLException && blame.getMessage().matches("Received fatal alert: handshake_failure")) {
            // SSLSocket throws SSLHandshakeException, but SSLEngine throws SSLException :(
            report.append("The remote server terminated our handshake attempt.\n");
            readLog(report, log, inputBuffer, outputBuffer);

            final SSLException diagnosis;
            try {
                diagnosis = (SSLException) blame.getClass().getConstructor(String.class).newInstance(report.toString());
                diagnosis.initCause(cause);
                throw diagnosis;
            } catch (InstantiationException | IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
                // If we get here this is a major bug. All Exception classes should implement a `(String message)` constructor.
                e.printStackTrace();
            }
            throw (SSLHandshakeException) blame;
        }
    }

    private static void readLog(StringBuilder builder, List<Transaction<?>> log, ByteBuffer inputBuffer, ByteBuffer outputBuffer) {
        inputBuffer.flip();
        outputBuffer.flip();
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
        // XXX: Refactor this into
        int initial = buffer.position();
        length = Math.min(initial + length, buffer.limit()) - initial;
        while (buffer.position() < initial + length) {
            final TLSPlaintext plaintext;
            try {
                plaintext = TLSPlaintext.parse(buffer);
            } catch (InvalidValue e) {
                builder.append(String.format("Invalid value decoding handshake: %s\n", e));
                e.printStackTrace();
                return;
            }
            //System.out.println(plaintext);

            ByteBuffer plainPayload = plaintext.getPayload();
            switch (plaintext.getContentType()) {
                case ChangeCipherSpec:
                case ApplicationData:
                    builder.append(String.format("%s\n", plaintext.getContentType()));
                    break;
                case Alert:
                    Alert alert;
                    try {
                        alert = TLSDecoder.decodeAlert(plainPayload);
                        builder.append(String.format("%s\n", alert));
                    } catch (InvalidValue e) {
                        builder.append(String.format("Invalid value decoding alert: %s\n", e));
                        return;
                    }
                    break;
                case Handshake:
                    // multiple handshake messages can be contained in a single TLSPlaintext
                    while (plainPayload.hasRemaining()) {
                        //System.out.println(plainPayload);
                        final TLSHandshake handshake;
                        try {
                            handshake = TLSDecoder.decodeHandshake(plainPayload);
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
                                    builder.append(String.format("  Certificate parsing failure: %s\n", e));
                                }
                                i++;
                            } // for : message.getChain()
                        }
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
        return new ObservableSocket(socket, this::read, this::write, this::exception);
    }

    @Override
    public SSLSocket observeIO(SSLSocket socket) {
        return new ObservableSSLSocket(socket, this::read, this::write, this::exception);
    }

    @Override
    public Socket observeExceptions(Socket socket) {
        return new ObservableSocket(socket, null, null, this::exception);
    }

    @Override
    public SSLSocket observeExceptions(SSLSocket socket) {
        return new ObservableSSLSocket(socket, null, null, this::exception);
    }
}
