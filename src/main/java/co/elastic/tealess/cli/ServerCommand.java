package co.elastic.tealess.cli;

import co.elastic.tealess.Bug;
import co.elastic.tealess.ConfigurationProblem;
import co.elastic.tealess.KeyStoreBuilder;
import co.elastic.tealess.SSLContextBuilder;
import co.elastic.tealess.cli.input.ArgsParser;
import co.elastic.tealess.cli.input.InetSocketAddressInput;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.ServerSocketChannel;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * Created by jls on 10/14/2017.
 */
public class ServerCommand implements Command {
    private static final Logger logger = LogManager.getLogger();

    private static final String DESCRIPTION = "Connect to an address with SSL/TLS and diagnose the result.";
    private final KeyStoreBuilder keys;
    private final KeyStoreBuilder trust;

    private void setAddress(InetSocketAddress address) {
        this.address = address;
    }

    private Path keyStore = null;
    private InetSocketAddress address = null;

    public ServerCommand() throws Bug {
        try {
            keys = new KeyStoreBuilder();
            trust = new KeyStoreBuilder();
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new Bug("'new KeyStoreBuilder' failed", e);
        }
    }

    private void setCAPath(Path path) throws CertificateException, KeyStoreException, IOException {
        logger.info("Adding to trust: capath {}", path);
        trust.addCAPath(path);
    }

    private void setTrustStore(Path path) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        trust.useKeyStore(path.toFile());
    }

    private void setKeyStore(Path path) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        if (keyStore != null) {
            keys.useKeyStore(keyStore.toFile());
        } else {
            keys.empty();
        }
    }

    @Override
    public ArgsParser getParser() {
        return new ArgsParser()
                .setDescription(DESCRIPTION)
                .addNamed(new Setting<Level>("log-level", "The log level").setDefaultValue(Level.WARN).parseWith(Level::valueOf), LogUtils::setLogLevel)
                .addNamed(new Setting<Path>("capath", "The path to a file containing one or more certificates to trust in PEM format.").parseWith(Paths::get), this::setCAPath)
                .addNamed(new Setting<Path>("truststore", "The path to a java keystore or pkcs12 file containing certificate authorities to trust").parseWith(Paths::get), this::setTrustStore)
                .addNamed(new Setting<Path>("keystore", "The path to a java keystore or pkcs12 file containing private key(s) and client certificates to use when connecting to a remote server.").parseWith(Paths::get), this::setKeyStore)
                .addPositional(new Setting<>("address", "The address in form of `host` or `host:port` to connect", new InetSocketAddressInput(443)), this::setAddress);
    }

    @Override
    public void run() throws ConfigurationProblem, Bug {
        SSLContextBuilder cb = new SSLContextBuilder();
        try {
            cb.setTrustStore(trust.buildKeyStore());
            cb.setKeyManagerFactory(keys.buildKeyManagerFactory());
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            throw new Bug("Failed building keystores", e);
        }

        final SSLContext ctx;
        try {
            ctx = cb.build();
        } catch (KeyManagementException | KeyStoreException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }

        EventLoopGroup group = new NioEventLoopGroup();

        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(group);
        bootstrap.channel(NioServerSocketChannel.class).handler(new ChannelInitializer<ServerSocketChannel>() {
            @Override
            protected void initChannel(ServerSocketChannel ch) throws Exception {
                ChannelPipeline pipeline = ch.pipeline();
                pipeline.addLast(new SimpleChannelInboundHandler<NioSocketChannel>() {
                                     @Override
                                     protected void channelRead0(ChannelHandlerContext chc, NioSocketChannel msg) throws Exception {
                                         System.out.println("New connection " + msg);
                                         group.register(msg);
                                         ChannelPipeline pipeline = msg.pipeline();
                                         SSLEngine engine = ctx.createSSLEngine();
                                         engine.setUseClientMode(false);
                                         SslHandler sslHandler = new SslHandler(engine);
                                         sslHandler.setHandshakeTimeoutMillis(1000);
                                         pipeline.addLast(sslHandler);
                                     }
                                 });
                        //pipeline.addLast(sslHandler);
            }
        });
        System.out.println("Binding " + address);
        ChannelFuture future = bootstrap.bind(address);
        try {
            System.out.println("Waiting...");
            future.sync();
        } catch (InterruptedException e1) {
            e1.printStackTrace();
        }
    }
}
