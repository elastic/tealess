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
package co.elastic.tealess.protocol;

import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.ByteBuffer;

import static org.junit.Assert.assertEquals;

public class TLSPlaintextTest {
  @Test
  public void parseValidHeader() throws IOException {
    URL url = getClass().getResource("/TLS_1_0_ClientHello");
    URLConnection connection = url.openConnection();
    int size = connection.getContentLength();
    InputStream stream = (InputStream) connection.getContent();

    byte[] data = new byte[size];
    int len = stream.read(data);
    assert (len == size);
    ByteBuffer buffer = ByteBuffer.wrap(data, 0, size);
    TLSPlaintext plaintext = TLSPlaintext.fromByteBuffer(buffer);

    assertEquals(plaintext.contentType, ContentType.Handshake);
    assertEquals(plaintext.protocolVersion, ProtocolVersion.TLS_1_0);
    assertEquals(plaintext.length, 196);
  }
}