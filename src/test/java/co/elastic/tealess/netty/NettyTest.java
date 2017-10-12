package co.elastic.tealess.netty;

import co.elastic.tealess.SSLContextBuilder;
import co.elastic.tealess.tls.CipherSuite;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.junit.After;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

public class NettyTest {
    private EventLoopGroup group = new NioEventLoopGroup();
    final SSLContextBuilder contextBuilder = new SSLContextBuilder();

    @After
    public void terminate() {
        group.shutdownGracefully();
    }

    @Test
    public void foo() throws InterruptedException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        //contextBuilder.setCipherSuites(new String[]{"FANCY"});
        //contextBuilder.setCipherSuites(new String[]{"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"});
        //SSLContext context = contextBuilder.build();
        SSLContext context = SSLContext.getDefault();
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(group).channel(NioSocketChannel.class).handler(new HTTPSInitializer(context));

        ChannelFuture future = bootstrap.connect("www.twitter.com", 80);
        System.out.println("1");
        Channel channel = future.sync().channel();
        System.out.println("2");
        channel.writeAndFlush("GET / HTTP/1.1\r\nHost: www.twitter.com\r\n\r\n");
        System.out.println("GET / HTTP/1.1\r\nHost: www.twitter.com\r\n\r\n");
        System.out.println("3");
        channel.closeFuture().sync();
    }
}
