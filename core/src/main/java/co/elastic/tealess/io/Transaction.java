package co.elastic.tealess.io;

public class Transaction<T> {
    public final Operation op;
    public final T value;
    private Transaction(Operation op, T value) {
        this.op = op;
        this.value = value;
        //this.timestamp = System.nanoTime(); // monotonic
    }
    //private final long timestamp;

    public static <Value> Transaction<Value> create(Operation op, Value value) {
        return new Transaction<>(op, value);
    }

    public String toString() {
        return String.format("[%s] %s", op, value);
    }

    public enum Operation {
        Input, Output, Exception
    }
}
