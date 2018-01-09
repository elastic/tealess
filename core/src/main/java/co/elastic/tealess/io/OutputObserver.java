package co.elastic.tealess.io;

public interface OutputObserver {
    void write(byte[] b, int off, int len);

    default void write(byte[] b) {
        write(b, 0, b.length);
    }

    default void write(int b) {
        write(new byte[]{(byte) b}, 0, 1);
    }
}
