package co.elastic.tealess.cli.input;

/**
 * Created by jls on 6/8/2017.
 */
public interface Validator<T> {
  Result validate(T value);

  class Result {
      private final boolean valid;
      private final String details;

    private Result(boolean valid, String details) {
      this.valid = valid;
      this.details = details;
    }

    public static Result Good() {
      return new Result(true, null);
    }

    public static Result Bad(String details) {
      return new Result(false, details);
    }

      public boolean isValid() {
          return valid;
      }

      public String getDetails() {
          return details;
      }
  }
}

