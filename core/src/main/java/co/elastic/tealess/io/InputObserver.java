package co.elastic.tealess.io;

public interface InputObserver {
    void read(byte[] b, int off, int len, int ret);

    default void read(int ret) {
        byte[] b;
        if (ret >= 0) {
            b = new byte[]{(byte) ret};
        } else {
            b = new byte[0];
        }
        read(b, 0, b.length, ret);
    }

    default void read(byte[] b, int ret) {
        read(b, 0, b.length, ret);
    }
}
