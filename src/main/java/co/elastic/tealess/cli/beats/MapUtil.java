package co.elastic.tealess.cli.beats;

import java.util.Map;
import java.util.TreeMap;

/**
 * Created by jls on 4/7/2017.
 */
public class MapUtil {
  public static Map<String, Object> flattenMap(Map<String, Object> in) {
    return flattenMap(in, new TreeMap<>(), "");
  }

  private static Map<String, Object> flattenMap(Map<String, Object> in, Map<String, Object> out, String prefix) {
    for (Map.Entry<String, Object> kv : in.entrySet()) {
      String key;
      if (prefix.isEmpty()) {
        key = kv.getKey();
      } else {
        key = String.format("%s.%s", prefix, kv.getKey());
      }

      Object value = kv.getValue();
      if (value instanceof Map) {
        flattenMap((Map<String, Object>) value, out, key);
      } else {
        out.put(key, value);
      }
    }

    return out;
  }
}
