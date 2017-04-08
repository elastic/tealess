package co.elastic.tealess;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Map;
import java.util.TreeMap;

import static org.junit.Assert.*;

/**
 * Created by jls on 4/7/2017.
 */
public class MapUtilTest {
  private Map<String, Object> input = new TreeMap<>();

  @Before
  public void setUp() throws Exception {
    input.put("hello", "world");

    Map<String, Object> one = new TreeMap<>();
    input.put("one", one);
    one.put("foo", "bar");
  }

  @Test
  public void testFlattening() {
    Map<String, Object> output = MapUtil.flattenMap(input);

    assertTrue("Flattened map should contain key 'one.foo'", output.containsKey("one.foo"));
    assertTrue("Flattened map should contain key 'hello'", output.containsKey("hello"));
  }

}