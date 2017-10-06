package co.elastic.tealess;

import co.elastic.tealess.tls.CipherSuite;

public class SSLState {
    private CipherSuite selectedCipherSuite;
    private CipherSuite cipherSuite;

    public void setCipherSuite(CipherSuite cipherSuite) {
        this.cipherSuite = cipherSuite;
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }
}
