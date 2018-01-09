package co.elastic.tealess;

import co.elastic.tealess.cli.beats.MapUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Created by jls on 4/7/2017.
 */
public class MapUtilTest {
    private final Map<String, Object> input = new TreeMap<>();

  @BeforeEach
  public void setUp() throws Exception {
    input.put("hello", "world");

    Map<String, Object> one = new TreeMap<>();
    input.put("one", one);
    one.put("foo", "bar");
  }

  @Test
  public void testFlattening() {
    Map<String, Object> output = MapUtil.flattenMap(input);

    assertTrue(output.containsKey("one.foo"), "Flattened map should contain key 'one.foo'");
    assertTrue(output.containsKey("hello"), "Flattened map should contain key 'hello'");
  }
}