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
package org.apache.log4j.jdbc;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.NDC;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.SimpleLayout;
import org.apache.log4j.VectorErrorHandler;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.xml.XLevel;

/**
 * Tests for CVE-2022-23305: JDBCAppender must never build SQL text out of
 * logging event data. The database is simulated by a recording JDBC
 * {@link Connection} handed out by {@link RecordingJDBCAppender}, so these
 * tests do not need a JDBC driver.
 */
public class JdbcAppenderTest extends TestCase {

  static final String INSERT_SQL =
    "insert into logs(level,location,message,message2) values('%p','%c','%m', ' %c %p %m')";

  static final String PARAMETERIZED_INSERT_SQL =
    "insert into logs(level,location,message,message2) values(?,?,?, ?)";

  static final String DROP_TABLE = "x'); DROP TABLE logs; --";

  /** SQL text passed to Connection.prepareStatement. */
  static final List PREPARED_SQL = new ArrayList();

  /** SQL text executed through a plain, unparameterized Statement. */
  static final List EXECUTED_SQL = new ArrayList();

  /** Rows stored through prepared statements, one String[] per row. */
  static final List ROWS = new ArrayList();

  Logger logger = Logger.getLogger(JdbcAppenderTest.class);

  public JdbcAppenderTest(final String name) {
    super(name);
  }

  protected void setUp() {
    PREPARED_SQL.clear();
    EXECUTED_SQL.clear();
    ROWS.clear();
  }

  protected void tearDown() {
    LogManager.shutdown();
    MDC.remove("user");
    NDC.remove();
  }

  public void testVerifyJdbcBufferSize1() {
    PropertyConfigurator.configure("input/jdbc_bufferSize1.properties");

    logger.debug("message with ' quote");
    assertEquals("batchSize=1, so messages should be added immediately",
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
        joinSorted(getMessagesFromDatabase()));

    logger.fatal("message with \" quote");

    assertEquals("batchSize=1, so two messages should be in DB after two logging calls",
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
        + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL message with \" quote\n",
        joinSorted(getMessagesFromDatabase()));

    assertNoPlainSql();
  }

  public void testVerifyJdbcBufferSize2() {
    PropertyConfigurator.configure("input/jdbc_bufferSize2.properties");

    logger.log(XLevel.TRACE, "xtrace message");
    logger.debug("message with ' quote");
    logger.info("message with \" quote");
    logger.warn("?");
    // bufferSize=2, so this messsage won't yet be stored to the db
    logger.error("m4");

    assertEquals(
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
        + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
        + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
        + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
        joinSorted(getMessagesFromDatabase()));

    logger.fatal("m5");

    assertEquals("Logging m5 message should trigger buffer flush for both m4 and m5",
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
        + "ERROR; org.apache.log4j.jdbc.JdbcAppenderTest; m4;  org.apache.log4j.jdbc.JdbcAppenderTest ERROR m4\n"
        + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; m5;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL m5\n"
        + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
        + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
        + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
        joinSorted(getMessagesFromDatabase()));

    assertNoPlainSql();
  }

  /**
   * A message closing the quoted literal must not change the statement.
   */
  public void testMessageCannotInjectSql() {
    String[] payloads = new String[] {
      DROP_TABLE,
      "x\\'); DROP TABLE logs; --",
      "'' OR 1=1; --",
      "%m'); DROP TABLE logs; --"
    };
    for (int i = 0; i < payloads.length; i++) {
      setUp();
      RecordingJDBCAppender appender = newAppender(INSERT_SQL);
      appender.doAppend(newEvent(Level.INFO, payloads[i]));

      assertNoPlainSql();
      assertPreparedOnly(PARAMETERIZED_INSERT_SQL);
      assertEquals(1, ROWS.size());
      String[] row = (String[]) ROWS.get(0);
      assertEquals("INFO", row[0]);
      assertEquals(payloads[i], row[2]);
      assertEquals(" " + logger.getName() + " INFO " + payloads[i], row[3]);
      appender.close();
    }
  }

  /**
   * Values taken from the MDC, the NDC, the thread name and the logger name
   * are attacker controlled as well and must also be bound as parameters.
   */
  public void testContextValuesCannotInjectSql() {
    RecordingJDBCAppender appender = newAppender(
        "insert into logs(level,location,message,message2) values('%p','%X{user}','%x', '%t / %c: %m')");
    Logger injectedLogger = Logger.getLogger(DROP_TABLE);
    String oldThreadName = Thread.currentThread().getName();
    MDC.put("user", DROP_TABLE);
    NDC.push(DROP_TABLE);
    try {
      Thread.currentThread().setName(DROP_TABLE);
      appender.doAppend(new LoggingEvent(Logger.class.getName(), injectedLogger,
                                         Level.WARN, "msg", null));
    } finally {
      Thread.currentThread().setName(oldThreadName);
    }

    assertNoPlainSql();
    assertPreparedOnly(PARAMETERIZED_INSERT_SQL);
    assertEquals(1, ROWS.size());
    String[] row = (String[]) ROWS.get(0);
    assertEquals("WARN", row[0]);
    assertEquals(DROP_TABLE, row[1]);
    assertEquals(DROP_TABLE, row[2]);
    assertEquals(DROP_TABLE + " / " + DROP_TABLE + ": msg", row[3]);
  }

  /**
   * Conversion patterns outside of a quoted literal are never replaced with
   * event data.
   */
  public void testUnquotedPatternIsNotExpanded() {
    String sql = "insert into logs(message) values(%m)";
    RecordingJDBCAppender appender = newAppender(sql);
    appender.doAppend(newEvent(Level.INFO, DROP_TABLE));

    assertNoPlainSql();
    assertPreparedOnly(sql);
  }

  /**
   * Layouts other than PatternLayout cannot be translated into a
   * parameterized statement and must not be executed as SQL.
   */
  public void testNonPatternLayoutIsRejected() {
    RecordingJDBCAppender appender = new RecordingJDBCAppender();
    VectorErrorHandler errorHandler = new VectorErrorHandler();
    appender.setErrorHandler(errorHandler);
    appender.setLayout(new SimpleLayout());
    appender.activateOptions();
    appender.doAppend(newEvent(Level.INFO, DROP_TABLE));

    assertNoPlainSql();
    assertEquals(0, PREPARED_SQL.size());
    assertEquals(0, ROWS.size());
    assertTrue(errorHandler.size() > 0);
    assertTrue(errorHandler.getException(0) instanceof IllegalArgumentException);
  }

  /**
   * getLogStatement() no longer formats the event into SQL text.
   */
  public void testLogStatementIsNotBuiltFromEvent() {
    RecordingJDBCAppender appender = newAppender(INSERT_SQL);
    assertEquals("", appender.getLogStatement(newEvent(Level.INFO, DROP_TABLE)));
  }

  /**
   * Closing the appender flushes the buffered events through a single
   * parameterized statement.
   */
  public void testCloseFlushesBufferWithPreparedStatement() {
    RecordingJDBCAppender appender = newAppender(INSERT_SQL);
    appender.setBufferSize(3);
    appender.doAppend(newEvent(Level.INFO, "m1"));
    appender.doAppend(newEvent(Level.ERROR, DROP_TABLE));
    assertEquals(0, ROWS.size());

    appender.close();

    assertNoPlainSql();
    assertPreparedOnly(PARAMETERIZED_INSERT_SQL);
    assertEquals(
        "ERROR; org.apache.log4j.jdbc.JdbcAppenderTest; " + DROP_TABLE
        + ";  org.apache.log4j.jdbc.JdbcAppenderTest ERROR " + DROP_TABLE + "\n"
        + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; m1;  org.apache.log4j.jdbc.JdbcAppenderTest INFO m1\n",
        joinSorted(getMessagesFromDatabase()));
  }

  private RecordingJDBCAppender newAppender(final String sql) {
    RecordingJDBCAppender appender = new RecordingJDBCAppender();
    appender.setErrorHandler(new VectorErrorHandler());
    appender.setSql(sql);
    appender.activateOptions();
    return appender;
  }

  private LoggingEvent newEvent(final Level level, final String message) {
    return new LoggingEvent(Logger.class.getName(), logger, level, message, null);
  }

  private static void assertNoPlainSql() {
    assertEquals("SQL built from event data was executed: " + EXECUTED_SQL,
                 0, EXECUTED_SQL.size());
  }

  private static void assertPreparedOnly(final String expectedSql) {
    assertTrue(PREPARED_SQL.size() > 0);
    for (int i = 0; i < PREPARED_SQL.size(); i++) {
      assertEquals(expectedSql, PREPARED_SQL.get(i));
    }
  }

  private static String joinSorted(final List list) {
    Collections.sort(list);
    StringBuffer sb = new StringBuffer();
    for (int i = 0; i < list.size(); i++) {
      String s = (String) list.get(i);
      sb.append(s).append('\n');
    }
    return sb.toString();
  }

  private static List getMessagesFromDatabase() {
    List res = new ArrayList();
    for (int i = 0; i < ROWS.size(); i++) {
      String[] row = (String[]) ROWS.get(i);
      res.add(row[0] + "; " + row[1] + "; " + row[2] + "; " + row[3]);
    }
    return res;
  }

  /**
   * JDBCAppender handing out a recording connection instead of a real one.
   */
  public static class RecordingJDBCAppender extends JDBCAppender {
    private final Connection recordingConnection = newRecordingConnection();

    public RecordingJDBCAppender() {
    }

    protected Connection getConnection() {
      return recordingConnection;
    }
  }

  static Connection newRecordingConnection() {
    return (Connection) newStub(Connection.class, new InvocationHandler() {
      public Object invoke(final Object proxy, final Method method, final Object[] args) {
        String name = method.getName();
        if ("prepareStatement".equals(name)) {
          PREPARED_SQL.add(args[0]);
          return newRecordingPreparedStatement();
        }
        if ("createStatement".equals(name)) {
          return newRecordingStatement();
        }
        return defaultValue(proxy, method, args);
      }
    });
  }

  static Statement newRecordingStatement() {
    return (Statement) newStub(Statement.class, new InvocationHandler() {
      public Object invoke(final Object proxy, final Method method, final Object[] args) {
        String name = method.getName();
        if (name.startsWith("execute") || "addBatch".equals(name)) {
          EXECUTED_SQL.add(args[0]);
        }
        return defaultValue(proxy, method, args);
      }
    });
  }

  static PreparedStatement newRecordingPreparedStatement() {
    final Map parameters = new HashMap();
    final List batch = new ArrayList();
    return (PreparedStatement) newStub(PreparedStatement.class, new InvocationHandler() {
      public Object invoke(final Object proxy, final Method method, final Object[] args) {
        String name = method.getName();
        int argCount = (args == null) ? 0 : args.length;
        if (name.startsWith("set") && argCount == 2 && args[0] instanceof Integer) {
          parameters.put(args[0], String.valueOf(args[1]));
          return null;
        }
        if (name.startsWith("execute") && argCount > 0) {
          EXECUTED_SQL.add(args[0]);
          return defaultValue(proxy, method, args);
        }
        if ("addBatch".equals(name) && argCount == 0) {
          batch.add(toRow(parameters));
          return null;
        }
        if ("executeBatch".equals(name)) {
          int[] counts = new int[batch.size()];
          ROWS.addAll(batch);
          batch.clear();
          return counts;
        }
        if ("execute".equals(name) || "executeUpdate".equals(name)) {
          ROWS.add(toRow(parameters));
          return defaultValue(proxy, method, args);
        }
        if ("clearParameters".equals(name)) {
          parameters.clear();
          return null;
        }
        return defaultValue(proxy, method, args);
      }
    });
  }

  static String[] toRow(final Map parameters) {
    String[] row = new String[parameters.size()];
    for (int i = 0; i < row.length; i++) {
      row[i] = (String) parameters.get(new Integer(i + 1));
    }
    return row;
  }

  static Object newStub(final Class type, final InvocationHandler handler) {
    return Proxy.newProxyInstance(JdbcAppenderTest.class.getClassLoader(),
                                  new Class[] { type }, handler);
  }

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
}
