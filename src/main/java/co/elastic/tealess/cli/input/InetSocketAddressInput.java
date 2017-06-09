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

package co.elastic.tealess.cli.input;

import co.elastic.tealess.cli.Setting.InputHandler;

import java.net.InetSocketAddress;

/**
 * Created by jls on 11/16/16.
 */
public class InetSocketAddressInput implements InputHandler<InetSocketAddress> {
  private int defaultPort;

  public InetSocketAddressInput(int defaultPort) {
    this.defaultPort = defaultPort;
  }

  @Override
  public InetSocketAddress parse(String text) {
    // TODO: fix this for ipv6 addresses
    int colon = text.lastIndexOf(':');
    if (colon == -1) {
      colon = text.length();
    }
    String host = text.substring(0, colon);

    int port = defaultPort;
    if (colon < text.length()) {
      port = Integer.parseInt(text.substring(colon + 1, text.length()));
    }
    return new InetSocketAddress(host, port);
  }

  @Override
  public Result validate(InetSocketAddress value) {
    // Maybe this could be better validation?
    if (value.getPort() >= 0 && value.getPort() <= 65535) {
      return Result.Good();
    } else {
      return Result.Bad("Port value must be between 1 and 65535. Port was set to " + value.getPort());
    }
  }
}
