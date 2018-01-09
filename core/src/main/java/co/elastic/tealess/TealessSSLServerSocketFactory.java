package co.elastic.tealess;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

/**
 * Created by jls on 10/14/2017.
 */
public class TealessSSLServerSocketFactory extends SSLServerSocketFactoryProxy {
    private final String[] cipherSuites;
    private final TrustManager[] trustManagers;

    public TealessSSLServerSocketFactory(SSLServerSocketFactory factory, String[] cipherSuites, TrustManager[] trustManagers) {
        super(factory);
        this.cipherSuites = cipherSuites;
        this.trustManagers = trustManagers;
    }

    @Override
    public ServerSocket createServerSocket() throws IOException {
        return new TealessSSLServerSocket((SSLServerSocket) super.createServerSocket(), cipherSuites, trustManagers);
    }

    @Override
    public ServerSocket createServerSocket(int i) throws IOException {
        return new TealessSSLServerSocket((SSLServerSocket) super.createServerSocket(i), cipherSuites, trustManagers);
    }

    @Override
    public ServerSocket createServerSocket(int i, int i1) throws IOException {
        return new TealessSSLServerSocket((SSLServerSocket) super.createServerSocket(i, i1), cipherSuites, trustManagers);
    }

    @Override
    public ServerSocket createServerSocket(int i, int i1, InetAddress inetAddress) throws IOException {
        return new TealessSSLServerSocket((SSLServerSocket) super.createServerSocket(i, i1, inetAddress), cipherSuites, trustManagers);
    }
}
