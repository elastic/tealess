
package co.elastic.tealess.netty;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpContentCompressor;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.HttpResponseEncoder;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

class HTTPSInitializer extends ChannelInitializer<SocketChannel> {

    private final SSLContext context;

    public HTTPSInitializer(SSLContext context) {
        this.context = context;
    }

    @Override
    protected void initChannel(SocketChannel ch) throws Exception {
        ChannelPipeline pipeline = ch.pipeline();

        SSLEngine engine = context.createSSLEngine();
        engine.setUseClientMode(true);
        SslHandler sslHandler = new SslHandler(engine);
        //pipeline.addLast(sslHandler);
        pipeline.addLast(new SimpleChannelInboundHandler<Object>() {

            @Override
            protected void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
                System.out.println(msg);
            }
        });
        //pipeline.addLast(new HttpRequestDecoder());
        //pipeline.addLast(new HttpResponseEncoder());
        //pipeline.addLast(new HttpContentCompressor());
        //pipeline.addLast(new HTTPClientHandler());
    }
}
