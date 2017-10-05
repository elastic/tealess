package co.elastic.tealess;

import java.net.Socket;

interface TLSObserver {
    Socket observeIO(Socket socket);

    Socket observeExceptions(Socket socket);
}
