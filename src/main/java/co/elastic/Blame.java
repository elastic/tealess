/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package co.elastic;

public class Blame {
  public static Throwable get(Throwable e) {
    Throwable i;
    while ((i = e.getCause()) != null) {
      //System.out.printf("Exception: %s caused by %s\n", e.getClass(), i.getClass());
      e = i;
    }
    return e;
  }

  /**
   * Does a Throwable's cause stack include the given type?
   * <p>
   * Example:
   * <p>
   * try {
   * ...
   * } catch (Exception e) {
   * if (Blame.on(e, sun.security.provider.certpath.SunCertPathBuilderException.class)) {
   * // e or some nested e.getCause() includes an exception of this type.
   * }
   * }
   */
  public static boolean on(Throwable e, Class type) {
    Throwable i = e;
    if (type.isInstance(i)) {
      return true;
    }
    while ((i = i.getCause()) != null) {
      if (type.isInstance(i)) {
        return true;
      }
    }
    return false;
  }
}
