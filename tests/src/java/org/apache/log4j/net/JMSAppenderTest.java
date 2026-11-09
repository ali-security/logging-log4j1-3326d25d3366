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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.jms.Topic;
import javax.jms.TopicConnectionFactory;
import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.spi.InitialContextFactory;

import junit.framework.TestCase;

import org.apache.log4j.Appender;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.ErrorHandler;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Tests that the JNDI names used by JMSAppender (TopicConnectionFactoryBindingName
 * and TopicBindingName) are restricted to the java: namespace, so that a
 * configuration cannot make the appender perform JNDI lookups against arbitrary
 * (e.g. LDAP or RMI) servers (CVE-2021-4104).
 */
public class JMSAppenderTest extends TestCase {

  static final String TCF_NAME = "java:comp/env/jms/TopicConnectionFactory";
  static final String TOPIC_NAME = "java:comp/env/jms/Topic";
  static final String LDAP_NAME = "ldap://127.0.0.1:1389/Exploit";

  static final String[] MALICIOUS_NAMES = new String[] {
    LDAP_NAME,
    "ldaps://127.0.0.1:1636/Exploit",
    "rmi://127.0.0.1:1099/Exploit",
    "dns://127.0.0.1/Exploit",
    "iiop://127.0.0.1:1050/Exploit",
    "corbaname::127.0.0.1:1050#Exploit",
    "nis://127.0.0.1/Exploit",
    "Exploit",
    "comp/env/jms/Topic"
  };

  public JMSAppenderTest(final String testName) {
    super(testName);
  }

  protected void setUp() {
    RecordingContextFactory.LOOKUPS.clear();
  }

  /**
   * A JNDI name outside of the java: namespace must be rejected before the
   * context is asked to resolve it.
   */
  public void testLookupRejectsNamesOutsideJavaNamespace() {
    JMSAppender appender = new JMSAppender();
    Context ctx = newRecordingContext();
    for (int i = 0; i < MALICIOUS_NAMES.length; i++) {
      String name = MALICIOUS_NAMES[i];
      NamingException caught = null;
      try {
        appender.lookup(ctx, name);
      } catch (NamingException e) {
        caught = e;
      }
      assertRestricted(name, caught);
    }
    assertEquals("JNDI lookups were performed: " + RecordingContextFactory.LOOKUPS,
                 0, RecordingContextFactory.LOOKUPS.size());
  }

  /**
   * Names in the java: namespace are still looked up.
   */
  public void testLookupAllowsJavaNamespace() throws NamingException {
    JMSAppender appender = new JMSAppender();
    Object result = appender.lookup(newRecordingContext(), TCF_NAME);
    assertTrue(result instanceof TopicConnectionFactory);
    assertEquals(1, RecordingContextFactory.LOOKUPS.size());
    assertEquals(TCF_NAME, RecordingContextFactory.LOOKUPS.get(0));
  }

  /**
   * A TopicConnectionFactoryBindingName pointing to an LDAP server must not
   * be looked up.
   */
  public void testActivateOptionsRejectsLdapTopicConnectionFactoryBindingName() {
    CapturingErrorHandler errorHandler = new CapturingErrorHandler();
    JMSAppender appender = createAppender(LDAP_NAME, TOPIC_NAME, errorHandler);
    appender.activateOptions();

    assertRestricted(LDAP_NAME, errorHandler.exception);
    assertEquals(0, RecordingContextFactory.LOOKUPS.size());
    assertNull(appender.topicConnection);
    assertNull(appender.topicPublisher);
  }

  /**
   * A TopicConnectionFactoryBindingName outside of the java: namespace must not
   * be resolved against the configured provider.
   */
  public void testActivateOptionsRejectsProviderTopicConnectionFactoryBindingName() {
    CapturingErrorHandler errorHandler = new CapturingErrorHandler();
    JMSAppender appender = createAppender("Exploit", TOPIC_NAME, errorHandler);
    appender.activateOptions();

    assertRestricted("Exploit", errorHandler.exception);
    assertEquals("JNDI lookups were performed: " + RecordingContextFactory.LOOKUPS,
                 0, RecordingContextFactory.LOOKUPS.size());
    assertNull(appender.topicConnection);
    assertNull(appender.topicPublisher);
  }

  /**
   * A TopicBindingName pointing to an LDAP server must not be looked up.
   */
  public void testActivateOptionsRejectsLdapTopicBindingName() {
    CapturingErrorHandler errorHandler = new CapturingErrorHandler();
    JMSAppender appender = createAppender(TCF_NAME, LDAP_NAME, errorHandler);
    appender.activateOptions();

    assertRestricted(LDAP_NAME, errorHandler.exception);
    assertEquals(1, RecordingContextFactory.LOOKUPS.size());
    assertEquals(TCF_NAME, RecordingContextFactory.LOOKUPS.get(0));
    assertNull(appender.topicPublisher);
    appender.close();
  }

  /**
   * A TopicBindingName outside of the java: namespace must not be resolved
   * against the configured provider.
   */
  public void testActivateOptionsRejectsProviderTopicBindingName() {
    CapturingErrorHandler errorHandler = new CapturingErrorHandler();
    JMSAppender appender = createAppender(TCF_NAME, "Exploit", errorHandler);
    appender.activateOptions();

    assertRestricted("Exploit", errorHandler.exception);
    assertEquals("JNDI lookups were performed: " + RecordingContextFactory.LOOKUPS,
                 1, RecordingContextFactory.LOOKUPS.size());
    assertEquals(TCF_NAME, RecordingContextFactory.LOOKUPS.get(0));
    assertNull(appender.topicPublisher);
    appender.close();
  }

  /**
   * The appender still activates when both names are in the java: namespace.
   */
  public void testActivateOptionsWithJavaNamespaceNames() {
    CapturingErrorHandler errorHandler = new CapturingErrorHandler();
    JMSAppender appender = createAppender(TCF_NAME, TOPIC_NAME, errorHandler);
    appender.activateOptions();

    assertNull("Unexpected error: " + errorHandler.message, errorHandler.exception);
    assertEquals(2, RecordingContextFactory.LOOKUPS.size());
    assertEquals(TCF_NAME, RecordingContextFactory.LOOKUPS.get(0));
    assertEquals(TOPIC_NAME, RecordingContextFactory.LOOKUPS.get(1));
    assertNotNull(appender.topicConnection);
    assertNotNull(appender.topicSession);
    assertNotNull(appender.topicPublisher);
    appender.close();
  }

  private static void assertRestricted(final String name, final Exception e) {
    assertNotNull("JNDI lookup of [" + name + "] was not rejected", e);
    assertTrue("Unexpected exception " + e, e instanceof NamingException);
    assertEquals(JNDIUtil.RESTRICTION_MSG + name, e.getMessage());
  }

  private static JMSAppender createAppender(final String tcfBindingName,
                                            final String topicBindingName,
                                            final ErrorHandler errorHandler) {
    JMSAppender appender = new JMSAppender();
    appender.setName("jms");
    appender.setErrorHandler(errorHandler);
    appender.setInitialContextFactoryName(RecordingContextFactory.class.getName());
    appender.setProviderURL("recording://localhost");
    appender.setTopicConnectionFactoryBindingName(tcfBindingName);
    appender.setTopicBindingName(topicBindingName);
    return appender;
  }

  /**
   * Returns a JNDI context which records every name it is asked to look up.
   * Only TCF_NAME and TOPIC_NAME are bound.
   */
  static Context newRecordingContext() {
    return (Context) newStub(Context.class, new InvocationHandler() {
      public Object invoke(final Object proxy, final Method method, final Object[] args)
          throws Throwable {
        if ("lookup".equals(method.getName()) && args != null && args.length == 1) {
          String name = String.valueOf(args[0]);
          RecordingContextFactory.LOOKUPS.add(name);
          if (TCF_NAME.equals(name)) {
            return newStub(TopicConnectionFactory.class);
          }
          if (TOPIC_NAME.equals(name)) {
            return newStub(Topic.class);
          }
          throw new NameNotFoundException(name);
        }
        return defaultValue(proxy, method, args);
      }
    });
  }

  static Object newStub(final Class type) {
    return newStub(type, new InvocationHandler() {
      public Object invoke(final Object proxy, final Method method, final Object[] args) {
        return defaultValue(proxy, method, args);
      }
    });
  }

  static Object newStub(final Class type, final InvocationHandler handler) {
    return Proxy.newProxyInstance(JMSAppenderTest.class.getClassLoader(),
                                  new Class[] { type }, handler);
  }

  /**
   * Interface return values are stubbed so that the JMS plumbing of the
   * appender works without a broker.
   */
  static Object defaultValue(final Object proxy, final Method method, final Object[] args) {
    String methodName = method.getName();
    if ("equals".equals(methodName)) {
      return (proxy == args[0]) ? Boolean.TRUE : Boolean.FALSE;
    }
    if ("hashCode".equals(methodName)) {
      return new Integer(System.identityHashCode(proxy));
    }
    if ("toString".equals(methodName)) {
      return "stub";
    }
    Class returnType = method.getReturnType();
    if (returnType.isInterface()) {
      return newStub(returnType);
    }
    if (returnType == Boolean.TYPE) {
      return Boolean.FALSE;
    }
    if (returnType == Integer.TYPE) {
      return new Integer(0);
    }
    if (returnType == Long.TYPE) {
      return new Long(0);
    }
    return null;
  }

  /**
   * InitialContextFactory returning a recording context.
   */
  public static final class RecordingContextFactory implements InitialContextFactory {
    static final List LOOKUPS = new ArrayList();

    public RecordingContextFactory() {
    }

    public Context getInitialContext(final Hashtable environment) {
      return newRecordingContext();
    }
  }

  /**
   * ErrorHandler keeping the last reported error.
   */
  static final class CapturingErrorHandler implements ErrorHandler {
    String message;
    Exception exception;

    public void setLogger(final Logger logger) {
    }

    public void error(final String message, final Exception e, final int errorCode) {
      this.message = message;
      this.exception = e;
    }

    public void error(final String message) {
      this.message = message;
    }

    public void error(final String message, final Exception e, final int errorCode,
                      final LoggingEvent event) {
      error(message, e, errorCode);
    }

    public void setAppender(final Appender appender) {
    }

    public void setBackupAppender(final Appender appender) {
    }

    public void activateOptions() {
    }
  }
}
