package co.elastic.tealess;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

/**
 * Created by jls on 10/14/2017.
 */
public class SSLServerSocketFactoryProxy extends SSLServerSocketFactory {
    private SSLServerSocketFactory factory;

    public SSLServerSocketFactoryProxy(SSLServerSocketFactory factory) {
        this.factory = factory;
    }

    public static ServerSocketFactory getDefault() {
        return SSLServerSocketFactory.getDefault();
    }

    public String[] getDefaultCipherSuites() {
        return factory.getDefaultCipherSuites();
    }

    public String[] getSupportedCipherSuites() {
        return factory.getSupportedCipherSuites();
    }

    public ServerSocket createServerSocket() throws IOException {
        return factory.createServerSocket();
    }

    public ServerSocket createServerSocket(int i) throws IOException {
        return factory.createServerSocket(i);
    }

    public ServerSocket createServerSocket(int i, int i1) throws IOException {
        return factory.createServerSocket(i, i1);
    }

    public ServerSocket createServerSocket(int i, int i1, InetAddress inetAddress) throws IOException {
        return factory.createServerSocket(i, i1, inetAddress);
    }

}
