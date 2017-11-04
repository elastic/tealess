package co.elastic.tealess;

import org.hamcrest.CoreMatchers;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeThat;

public class SSLContextBuilderTest {
  SSLContextBuilder builder = new SSLContextBuilder();

  @Test(expected = IllegalArgumentException.class)
  public void setCipherSuitesWithInvalidCipherSuite() throws Exception {
    builder.setCipherSuites(new String[]{"foo"});
  }

  @Test
  public void setCipherSuitesWithValidCipherSuite() throws Exception {
  }

  @Test
  public void setCipherSuitesThatMayRequireJCEUnlimitedStrengthCrypto() throws Exception {
    String aes256suite = "TLS_RSA_WITH_AES_256_CBC_SHA256";
    // This may or may not fail -- depending on the JVM configuration.
    // This test can go away, I think, once we require Java 8u162 or higher, due to this being fixed: https://bugs.openjdk.java.net/browse/JDK-8170157
    SSLContext context = SSLContext.getDefault();
    List<String> supportedCiphers = Arrays.asList(context.getSupportedSSLParameters().getCipherSuites());

    // This test assumes that the default supported ciphers does *not* include any AES 256 cipher suites (aka: "Unlimited Strength Cryptography" is missing).
    assumeThat(supportedCiphers, not(CoreMatchers.hasItem(aes256suite)));
    try {
      builder.setCipherSuites(new String[]{aes256suite});
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), CoreMatchers.containsString("Java Cryptography Extension"));
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void setProtocolsWithInvalidProtocol() throws Exception {
    builder.setProtocols(new String[]{"SSL100"});
  }


}