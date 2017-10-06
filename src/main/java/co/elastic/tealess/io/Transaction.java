package co.elastic.tealess.io;

public class Transaction<T> {
    public enum Operation {
        Input, Output, Exception
    }

    public final Operation op;
    public final T value;
    private final long timestamp;

    private Transaction(Operation op, T value) {
        this.op = op;
        this.value = value;
        this.timestamp = System.nanoTime(); // monotonic
    }

    public static <Value> Transaction<Value> create(Operation op, Value value) {
        return new Transaction<>(op, value);
    }

    public String toString() {
        return String.format("[%s] %s bytes", op, value);
    }
}
