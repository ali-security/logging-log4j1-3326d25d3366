/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.VectorAppender;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.RootLogger;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * Builds the CVE-2023-26464 attack payload: deeply nested HashSets
     * that form a DAG causing O(2^N) hashCode() computation when the
     * structure is deserialized.
     */
    private static Set buildNestedHashSetPayload() {
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        return root;
    }

    private static LoggingEvent createEvent(String message, Map properties) {
        Logger logger = Logger.getLogger(HardenedObjectInputStreamTest.class);
        return new LoggingEvent(HardenedObjectInputStreamTest.class.getName(),
                logger, System.currentTimeMillis(), Level.INFO, message,
                "main", null, null, null, properties);
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        // Build the CVE-2023-26464 attack payload: deeply nested HashSets
        // that form a DAG causing O(2^N) hashCode() computation
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        byte[] serialized = serialize(root);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        try {
            hois.readObject();
            fail("Deeply nested HashSet should be rejected due to collection count limit");
        } catch (InvalidObjectException e) {
            // Our resolveObject-based collection count limit caught it (pre-JDK 9)
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") >= 0);
        } catch (java.io.InvalidClassException e) {
            // On JDK 9+, the built-in ObjectInputFilter may reject it first
            // with "filter status: REJECTED". Either way, the attack is blocked.
        } finally {
            hois.close();
        }
    }

    /**
     * CVE-2023-26464 with a HashMap: nested maps used as keys form the
     * same exponential hashCode() DAG as the HashSet variant.
     */
    public void testDeeplyNestedHashMapRejected() throws Exception {
        Map root = new HashMap();
        Map s1 = root;
        Map s2 = new HashMap();
        for (int i = 0; i < 100; i++) {
            Map t1 = new HashMap();
            Map t2 = new HashMap();
            t1.put("foo", "bar");
            s1.put(t1, "t1");
            s1.put(t2, "t2");
            s2.put(t1, "t1");
            s2.put(t2, "t2");
            s1 = t1;
            s2 = t2;
        }
        byte[] serialized = serialize(root);

        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialized), new String[0]);
        try {
            hois.readObject();
            fail("Deeply nested HashMap should be rejected due to collection count limit");
        } catch (InvalidObjectException e) {
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") >= 0);
        } finally {
            hois.close();
        }
    }

    /**
     * CVE-2023-26464 with a Hashtable, the type log4j uses for the MDC of
     * a LoggingEvent: a deeply nested Hashtable must be rejected.
     */
    public void testDeeplyNestedHashtableRejected() throws Exception {
        Hashtable root = new Hashtable();
        Hashtable current = root;
        for (int i = 0; i < 100; i++) {
            Hashtable child = new Hashtable();
            current.put("child", child);
            current = child;
        }
        current.put("leaf", "value");
        byte[] serialized = serialize(root);

        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialized), new String[0]);
        try {
            hois.readObject();
            fail("Deeply nested Hashtable should be rejected due to collection count limit");
        } catch (InvalidObjectException e) {
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") >= 0);
        } finally {
            hois.close();
        }
    }

    /**
     * CVE-2023-26464 via the SocketAppender/Chainsaw wire format: a
     * LoggingEvent whose MDC carries the nested HashSet payload must be
     * rejected by HardenedLoggingEventInputStream.readAdaptedObject, the
     * call used by SocketNode and the Chainsaw LoggingReceiver.
     */
    public void testNestedPayloadInLoggingEventRejected() throws Exception {
        Hashtable properties = new Hashtable();
        properties.put("payload", buildNestedHashSetPayload());
        byte[] serialized = serialize(createEvent("malicious", properties));

        HardenedLoggingEventInputStream hleis = new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(serialized));
        try {
            hleis.readAdaptedObject();
            fail("LoggingEvent carrying deeply nested collections should be rejected");
        } catch (InvalidObjectException e) {
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") >= 0);
        } finally {
            hleis.close();
        }
    }

    /**
     * Each event read with readAdaptedObject gets its own collection
     * budget, so a long-lived connection sending many legitimate events
     * with an MDC is not cut off.
     */
    public void testReadAdaptedObjectResetsCollectionBudget() throws Exception {
        int eventCount = 2 * HardenedObjectInputStream.MAX_COLLECTION_COUNT + 1;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < eventCount; i++) {
            Hashtable properties = new Hashtable();
            properties.put("key", "value" + i);
            oos.writeObject(createEvent("message " + i, properties));
        }
        oos.close();

        HardenedLoggingEventInputStream hleis = new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(bos.toByteArray()));
        try {
            for (int i = 0; i < eventCount; i++) {
                LoggingEvent event = (LoggingEvent) hleis.readAdaptedObject();
                assertEquals("message " + i, event.getRenderedMessage());
                assertEquals("value" + i, event.getMDC("key"));
            }
        } finally {
            hleis.close();
        }
    }

    /**
     * End-to-end CVE-2023-26464 check of the SocketServer receiving side:
     * SocketNode must drop the connection on a nested-collection payload
     * promptly instead of hanging in hashCode() computation, while still
     * logging the legitimate event that preceded it.
     */
    public void testSocketNodeRejectsNestedCollectionPayload() throws Exception {
        Hashtable maliciousProperties = new Hashtable();
        maliciousProperties.put("payload", buildNestedHashSetPayload());

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(createEvent("before", null));
        oos.writeObject(createEvent("malicious", maliciousProperties));
        oos.writeObject(createEvent("after", null));
        oos.close();
        byte[] payload = bos.toByteArray();

        Hierarchy hierarchy = new Hierarchy(new RootLogger(Level.ALL));
        VectorAppender appender = new VectorAppender();
        hierarchy.getRootLogger().addAppender(appender);

        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        ServerSocket serverSocket = new ServerSocket(0, 1, loopback);
        Socket client = null;
        Socket accepted = null;
        try {
            client = new Socket(loopback, serverSocket.getLocalPort());
            accepted = serverSocket.accept();

            OutputStream out = client.getOutputStream();
            out.write(payload);
            out.flush();

            Thread nodeThread = new Thread(new SocketNode(accepted, hierarchy));
            nodeThread.setDaemon(true);
            nodeThread.start();
            nodeThread.join(30000);

            assertFalse("SocketNode should close the connection instead of hanging",
                    nodeThread.isAlive());
            assertEquals(1, appender.getVector().size());
            assertEquals("before",
                    ((LoggingEvent) appender.getVector().elementAt(0)).getRenderedMessage());
        } finally {
            if (client != null) {
                client.close();
            }
            if (accepted != null) {
                accepted.close();
            }
            serverSocket.close();
        }
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }
}
