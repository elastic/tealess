package co.elastic.tealess;

import javax.net.ssl.SSLSocket;
import java.net.Socket;

interface TLSObserver {
    Socket observeIO(Socket socket);

    Socket observeExceptions(Socket socket);

    SSLSocket observeIO(SSLSocket socket);

    SSLSocket observeExceptions(SSLSocket socket);
}
