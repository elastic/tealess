package co.elastic.tealess.tls;

/**
 * Created by jls on 4/30/2017.
 */
public class Version {
  private byte major;
  private byte minor;

  public Version(byte major, byte minor) {
    this.major = major;
    this.minor = minor;
  }

  public String toString() {
    switch (major) {
      case 2:
        return "SSL 2.0?";
      case 3:
        switch (minor) {
          case 0:
            return "SSL 3.0";
          case 1:
            return "TLS 1.0";
          case 2:
            return "TLS 1.1";
          case 3:
            return "TLS 1.2";
        }
      default:
        return "UNKNOWN_VERSION(" + major + "," + minor + ")";
    }
  }


}
