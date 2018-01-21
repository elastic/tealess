package co.elastic.tealess.io;

import java.io.IOException;

public interface ExceptionObserver {
  void exception(Throwable cause) throws IOException;
}
