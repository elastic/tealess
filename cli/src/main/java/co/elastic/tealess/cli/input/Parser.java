package co.elastic.tealess.cli.input;

public interface Parser<T> {
  T parse(String text) throws InvalidValue;
}
