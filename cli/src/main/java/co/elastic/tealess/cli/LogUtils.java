package co.elastic.tealess.cli;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;

/**
 * Created by jls on 6/8/2017.
 */
class LogUtils {
  private static final String PACKAGE_LOGGER_NAME = "co.elastic";

  static void setLogLevel(Level level) {
    if (level != null) {
      LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
      ctx.getConfiguration().getLoggerConfig(PACKAGE_LOGGER_NAME).setLevel(level);
      ctx.updateLoggers();
    }
  }

}
