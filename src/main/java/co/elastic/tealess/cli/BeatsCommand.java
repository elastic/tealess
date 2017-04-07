package co.elastic.tealess.cli;

import co.elastic.Bug;
import co.elastic.tealess.ConfigurationProblem;
import co.elastic.tealess.cli.input.ArgsParser;
import co.elastic.tealess.cli.input.ParserResult;
import co.elastic.tealess.cli.input.PathInput;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.file.Path;

/**
 * Created by jls on 4/6/2017.
 */
public class BeatsCommand implements Command {
  private static final Logger logger = LogManager.getLogger();
  public static final String DESCRIPTION = "Test TLS settings from an Elastic Beats configuration.";

  private final ArgsParser parser = new ArgsParser();
  private final Setting<Path> config = parser.addPositional(new Setting<Path>("config", "The path to the beats yaml", PathInput.singleton));

  @Override
  public ParserResult parse(String[] args) throws ConfigurationProblem {
    parser.setDescription(DESCRIPTION);
    ParserResult result = parser.parse(args);
    if (!result.getSuccess()) {
      if (result.getDetails() != null) {
        System.out.println(result.getDetails());
        System.out.println();
      }
      parser.showHelp("beats");
      return result;
    }

    return result;
  }

  @Override
  public void run() throws ConfigurationProblem, Bug {
    System.out.println("Running with " + config.getValue());
  }
}
