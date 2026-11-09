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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;

import org.apache.log4j.Layout;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.spi.ErrorCode;
import org.apache.log4j.spi.LoggingEvent;


/**
  The JDBCAppender provides for sending log events to a database.
  
 <p><b><font color="#FF2222">WARNING: This version of JDBCAppender
 is very likely to be completely replaced in the future. Moreoever,
 it does not log exceptions</font></b>.

  <p>Each append call adds to an <code>ArrayList</code> buffer.  When
  the buffer is filled each log event is placed in a sql statement
  (configurable) and executed.

  <b>BufferSize</b>, <b>db URL</b>, <b>User</b>, & <b>Password</b> are
  configurable options in the standard log4j ways.

  <p>The <code>setSql(String sql)</code> sets the SQL statement to be
  used for logging -- this statement is sent to a
  <code>PatternLayout</code> (either created automaticly by the
  appender or added by the user).  Therefore by default all the
  conversion patterns in <code>PatternLayout</code> can be used
  inside of the statement.  (see the test cases for examples)

  <p>The statement is never built by formatting the logging event into
  SQL text, which made it vulnerable to SQL injection (CVE-2022-23305).
  Instead, every single-quoted string literal of the statement holding
  conversion patterns, e.g. <code>'%m'</code>, is replaced with a bind
  variable of a {@link java.sql.PreparedStatement PreparedStatement}
  and its formatted value is bound as a <code>String</code>.  Literals
  without conversion patterns are kept as is.  Only
  <code>org.apache.log4j.PatternLayout</code> is supported as layout.

  <p>As of the fix for CVE-2022-23305 {@link #getLogStatement} is no
  longer in use.

  <p>For use as a base class:

    <ul>

    <li>Override <code>getConnection()</code> to pass any connection
    you want.  Typically this is used to enable application wide
    connection pooling.

     <li>Override <code>closeConnection(Connection con)</code> -- if
     you override getConnection make sure to implement
     <code>closeConnection</code> to handle the connection you
     generated.  Typically this would return the connection to the
     pool it came from.

    </ul>

    @author Kevin Steppe (<A HREF="mailto:ksteppe@pacbell.net">ksteppe@pacbell.net</A>)

*/
public class JDBCAppender extends org.apache.log4j.AppenderSkeleton
    implements org.apache.log4j.Appender {

  private static final IllegalArgumentException ILLEGAL_PATTERN_FOR_SECURE_EXEC =
    new IllegalArgumentException(
      "Only org.apache.log4j.PatternLayout is supported for now due to CVE-2022-23305");

  /**
   * URL of the DB for default connection handling
   */
  protected String databaseURL = "jdbc:odbc:myDB";

  /**
   * User to connect as for default connection handling
   */
  protected String databaseUser = "me";

  /**
   * User to use for default connection handling
   */
  protected String databasePassword = "mypassword";

  /**
   * Connection used by default.  The connection is opened the first time it
   * is needed and then held open until the appender is closed (usually at
   * garbage collection).  This behavior is best modified by creating a
   * sub-class and overriding the <code>getConnection</code> and
   * <code>closeConnection</code> methods.
   */
  protected Connection connection = null;

  /**
   * Stores the string given to the pattern layout for conversion into a SQL
   * statement, eg: insert into LogTable (Thread, Class, Message) values
   * ("%t", "%c", "%m").
   *
   * Be careful of quotes in your messages!
   *
   * Also see PatternLayout.
   */
  protected String sqlStatement = "";

  /**
   * Translates the conversion pattern into a parameterized SQL statement.
   */
  private JdbcPatternParser preparedStatementParser;

  /**
   * Conversion pattern {@link #preparedStatementParser} was built from.
   */
  private String preparedStatementPattern;

  /**
   * size of LoggingEvent buffer before writting to the database.
   * Default is 1.
   */
  protected int bufferSize = 1;

  /**
   * ArrayList holding the buffer of Logging Events.
   */
  protected ArrayList buffer;

  /**
   * Helper object for clearing out the buffer
   */
  protected ArrayList removes;
  
  private boolean locationInfo = false;

  public JDBCAppender() {
    super();
    buffer = new ArrayList(bufferSize);
    removes = new ArrayList(bufferSize);
  }

  /**
   * Gets whether the location of the logging request call
   * should be captured.
   *
   * @since 1.2.16
   * @return the current value of the <b>LocationInfo</b> option.
   */
  public boolean getLocationInfo() {
    return locationInfo;
  }
  
  /**
   * The <b>LocationInfo</b> option takes a boolean value. By default, it is
   * set to false which means there will be no effort to extract the location
   * information related to the event. As a result, the event that will be
   * ultimately logged will likely to contain the wrong location information
   * (if present in the log format).
   * <p/>
   * <p/>
   * Location information extraction is comparatively very slow and should be
   * avoided unless performance is not a concern.
   * </p>
   * @since 1.2.16
   * @param flag true if location information should be extracted.
   */
  public void setLocationInfo(final boolean flag) {
    locationInfo = flag;
  }
  

  /**
   * Adds the event to the buffer.  When full the buffer is flushed.
   */
  public void append(LoggingEvent event) {
    event.getNDC();
    event.getThreadName();
    // Get a copy of this thread's MDC.
    event.getMDCCopy();
    if (locationInfo) {
      event.getLocationInformation();
    }
    event.getRenderedMessage();
    event.getThrowableStrRep();
    buffer.add(event);

    if (buffer.size() >= bufferSize)
      flushBuffer();
  }

  /**
   * <p><b>As of the fix for CVE-2022-23305 getLogStatement is no longer
   * in use.</b> Formatting the event into SQL text allowed SQL injection,
   * the events are now inserted using a
   * {@link java.sql.PreparedStatement PreparedStatement}.</p>
   *
   * @param event
   */
  protected String getLogStatement(LoggingEvent event) {
    return "";
  }

  /**
   *
   * Override this to provide an alertnate method of getting
   * connections (such as caching).  One method to fix this is to open
   * connections at the start of flushBuffer() and close them at the
   * end.  I use a connection pool outside of JDBCAppender which is
   * accessed in an override of this method.
   * */
  protected void execute(String sql) throws SQLException {

    Connection con = null;
    Statement stmt = null;

    try {
        con = getConnection();

        stmt = con.createStatement();
        stmt.executeUpdate(sql);
    } finally {
        if(stmt != null) {
            stmt.close();
        }
        closeConnection(con);
    }

    //System.out.println("Execute: " + sql);
  }


  /**
   * Override this to return the connection to a pool, or to clean up the
   * resource.
   *
   * The default behavior holds a single connection open until the appender
   * is closed (typically when garbage collected).
   */
  protected void closeConnection(Connection con) {
  }

  /**
   * Override this to link with your connection pooling system.
   *
   * By default this creates a single connection which is held open
   * until the object is garbage collected.
   */
  protected Connection getConnection() throws SQLException {
      if (!DriverManager.getDrivers().hasMoreElements())
	     setDriver("sun.jdbc.odbc.JdbcOdbcDriver");

      if (connection == null) {
        connection = DriverManager.getConnection(databaseURL, databaseUser,
					databasePassword);
      }

      return connection;
  }

  /**
   * Closes the appender, flushing the buffer first then closing the default
   * connection if it is open.
   */
  public void close()
  {
    flushBuffer();

    try {
      if (connection != null && !connection.isClosed())
          connection.close();
    } catch (SQLException e) {
        errorHandler.error("Error closing connection", e, ErrorCode.GENERIC_FAILURE);
    }
    this.closed = true;
  }

  /**
   * loops through the buffer of LoggingEvents and inserts them into the
   * database using a {@link java.sql.PreparedStatement PreparedStatement}
   * built from the conversion pattern, so that the data of the events is
   * never part of the SQL text.
   * Errors are sent to the errorHandler.
   */
  public void flushBuffer() {
    if (buffer.isEmpty()) {
      return;
    }
    //Do the actual logging
    removes.ensureCapacity(buffer.size());
    removes.addAll(buffer);

    // remove from the buffer any events that are reported
    buffer.removeAll(removes);

    try {
      flushBufferSecure(removes);
    } finally {
      // clear the buffer of reported events
      removes.clear();
    }
  }

  private void flushBufferSecure(ArrayList events) {
    JdbcPatternParser parser = getPreparedStatementParser();
    if (parser == null) {
      return;
    }
    Connection con = null;
    boolean useBatch = events.size() > 1;
    try {
      con = getConnection();
      PreparedStatement ps = con.prepareStatement(parser.getParameterizedSql());
      safelyInsertIntoDB(parser, events, useBatch, ps);
    } catch (SQLException e) {
      errorHandler.error("Failed to append messages sql", e,
                         ErrorCode.FLUSH_FAILURE);
    } finally {
      if (con != null) {
        closeConnection(con);
      }
    }
  }

  private void safelyInsertIntoDB(JdbcPatternParser parser, ArrayList events,
                                  boolean useBatch, PreparedStatement ps)
      throws SQLException {
    try {
      for (int i = 0; i < events.size(); i++) {
        LoggingEvent logEvent = (LoggingEvent) events.get(i);
        try {
          parser.setParameters(ps, logEvent);
          if (useBatch) {
            ps.addBatch();
          }
        } catch (SQLException e) {
          errorHandler.error("Failed to append parameters", e,
                             ErrorCode.FLUSH_FAILURE);
        }
      }
      if (useBatch) {
        ps.executeBatch();
      } else {
        ps.execute();
      }
    } finally {
      try {
        ps.close();
      } catch (SQLException ignored) {
      }
    }
  }

  /**
   * Returns the parser translating the conversion pattern of the layout
   * into a parameterized SQL statement, or null when the layout is not a
   * <code>PatternLayout</code>.
   */
  private JdbcPatternParser getPreparedStatementParser() {
    Layout currentLayout = getLayout();
    String pattern = null;
    if (currentLayout != null && currentLayout.getClass() == PatternLayout.class) {
      pattern = ((PatternLayout) currentLayout).getConversionPattern();
    }
    if (pattern == null) {
      errorHandler.error("Failed to convert pattern " + currentLayout + " to SQL",
                         ILLEGAL_PATTERN_FOR_SECURE_EXEC, ErrorCode.MISSING_LAYOUT);
      return null;
    }
    if (preparedStatementParser == null || !pattern.equals(preparedStatementPattern)) {
      preparedStatementParser = new JdbcPatternParser(pattern);
      preparedStatementPattern = pattern;
    }
    return preparedStatementParser;
  }


  /** closes the appender before disposal */
  public void finalize() {
    close();
  }


  /**
   * JDBCAppender requires a layout.
   * */
  public boolean requiresLayout() {
    return true;
  }


  /**
   *
   */
  public void setSql(String s) {
    sqlStatement = s;
    if (getLayout() == null) {
        this.setLayout(new PatternLayout(s));
    }
    else {
        ((PatternLayout)getLayout()).setConversionPattern(s);
    }
  }


  /**
   * Returns pre-formated statement eg: insert into LogTable (msg) values ("%m")
   */
  public String getSql() {
    return sqlStatement;
  }


  public void setUser(String user) {
    databaseUser = user;
  }


  public void setURL(String url) {
    databaseURL = url;
  }


  public void setPassword(String password) {
    databasePassword = password;
  }


  public void setBufferSize(int newBufferSize) {
    bufferSize = newBufferSize;
    buffer.ensureCapacity(bufferSize);
    removes.ensureCapacity(bufferSize);
  }


  public String getUser() {
    return databaseUser;
  }


  public String getURL() {
    return databaseURL;
  }


  public String getPassword() {
    return databasePassword;
  }


  public int getBufferSize() {
    return bufferSize;
  }


  /**
   * Ensures that the given driver class has been loaded for sql connection
   * creation.
   */
  public void setDriver(String driverClass) {
    try {
      Class.forName(driverClass);
    } catch (Exception e) {
      errorHandler.error("Failed to load driver", e,
			 ErrorCode.GENERIC_FAILURE);
    }
  }
}

