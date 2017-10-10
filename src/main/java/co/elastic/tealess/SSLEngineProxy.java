package co.elastic.tealess;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;

class SSLEngineProxy extends SSLEngine {
    private SSLEngine engine;

    public SSLEngineProxy(SSLEngine engine) {
        this.engine = engine;
    }

    @Override
    public String getPeerHost() {
        return engine.getPeerHost();
    }

    @Override
    public int getPeerPort() {
        return engine.getPeerPort();
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer byteBuffer, ByteBuffer byteBuffer1) throws SSLException {
        return engine.wrap(byteBuffer, byteBuffer1);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] byteBuffers, ByteBuffer byteBuffer) throws SSLException {
        return engine.wrap(byteBuffers, byteBuffer);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] byteBuffers, int i, int i1, ByteBuffer byteBuffer) throws SSLException {
        return engine.wrap(byteBuffers, i, i1, byteBuffer);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer byteBuffer, ByteBuffer byteBuffer1) throws SSLException {
        return engine.unwrap(byteBuffer, byteBuffer1);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer byteBuffer, ByteBuffer[] byteBuffers) throws SSLException {
        return engine.unwrap(byteBuffer, byteBuffers);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer byteBuffer, ByteBuffer[] byteBuffers, int i, int i1) throws SSLException {
        return engine.unwrap(byteBuffer, byteBuffers, i, i1);
    }

    @Override
    public Runnable getDelegatedTask() {
        return engine.getDelegatedTask();
    }

    @Override
    public void closeInbound() throws SSLException {
        engine.closeInbound();
    }

    @Override
    public boolean isInboundDone() {
        return engine.isInboundDone();
    }

    @Override
    public void closeOutbound() {
        engine.closeOutbound();
    }

    @Override
    public boolean isOutboundDone() {
        return engine.isOutboundDone();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return engine.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return engine.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] strings) {
        engine.setEnabledCipherSuites(strings);
    }

    @Override
    public String[] getSupportedProtocols() {
        return engine.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return engine.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] strings) {
        engine.setEnabledProtocols(strings);
    }

    @Override
    public SSLSession getSession() {
        return engine.getSession();
    }

    @Override
    public SSLSession getHandshakeSession() {
        return engine.getHandshakeSession();
    }

    @Override
    public void beginHandshake() throws SSLException {
        engine.beginHandshake();
    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return engine.getHandshakeStatus();
    }

    @Override
    public void setUseClientMode(boolean b) {
        engine.setUseClientMode(b);
    }

    @Override
    public boolean getUseClientMode() {
        return engine.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean b) {
        engine.setNeedClientAuth(b);
    }

    @Override
    public boolean getNeedClientAuth() {
        return engine.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean b) {
        engine.setWantClientAuth(b);
    }

    @Override
    public boolean getWantClientAuth() {
        return engine.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean b) {
        engine.setEnableSessionCreation(b);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return engine.getEnableSessionCreation();
    }

    @Override
    public SSLParameters getSSLParameters() {
        return engine.getSSLParameters();
    }

    @Override
    public void setSSLParameters(SSLParameters sslParameters) {
        engine.setSSLParameters(sslParameters);
    }
}
