package co.elastic.tealess.cli;

/**
 * Created by jls on 4/7/2017.
 */
public class ValidationResult {
  private boolean valid;
  private String details;

  private ValidationResult(boolean valid, String details) {
    this.valid = valid;
    this.details = details;
  }

  public boolean isValid() {
    return valid;
  }

  public String getDetails() {
    return details;
  }

  public static ValidationResult Good() {
    return new ValidationResult(true, null);
  }

  public static ValidationResult Bad(String details) {
    return new ValidationResult(false, details);
  }
}
