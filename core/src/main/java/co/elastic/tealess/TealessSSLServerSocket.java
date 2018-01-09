package co.elastic.tealess;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManager;
import java.io.IOException;

/**
 * Created by jls on 10/14/2017.
 */
public class TealessSSLServerSocket extends SSLServerSocketProxy {
    private final SSLServerSocket serverSocket;
    private final TrustManager[] trustManagers;
    private String[] cipherSuites;

    public TealessSSLServerSocket(SSLServerSocket serverSocket, String[] cipherSuites, TrustManager[] trustManagers) throws IOException {
        super(serverSocket);

        this.serverSocket = serverSocket;
        this.cipherSuites = cipherSuites;
        this.trustManagers = trustManagers;
    }

    @Override
    public void setEnabledCipherSuites(String[] cipherSuites) {
        super.setEnabledCipherSuites(cipherSuites);
        this.cipherSuites = cipherSuites;
    }

    // XXX: IMPLEMENT ACCEPT()
}
