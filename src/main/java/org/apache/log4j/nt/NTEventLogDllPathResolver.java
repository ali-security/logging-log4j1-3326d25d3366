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

package org.apache.log4j.nt;

import java.io.File;

/**
 * Resolves the fully qualified path of the NTEventLogAppender DLL from the
 * {@value #DLL_PATH_PROPERTY} system property.
 *
 * <p>This class has no native static initialization, so the resolution
 * logic can be used (and tested) independently of loading the DLL.
 */
final class NTEventLogDllPathResolver {

  static final String DLL_PATH_PROPERTY = "log4j.nteventlog.dll.path";

  private NTEventLogDllPathResolver() {
  }

  /**
   * Resolves the DLL path from the {@value #DLL_PATH_PROPERTY} system property.
   * Returns the absolute path if the property is set and points to an existing
   * file with an absolute path; returns {@code null} otherwise.
   */
  static String resolveConfiguredDllPath() {
      try {
          String dllPath = System.getProperty(DLL_PATH_PROPERTY);
          if (dllPath == null || dllPath.trim().length() == 0) {
              return null;
          }
          dllPath = dllPath.trim();
          File dllFile = new File(dllPath);
          if (!dllFile.isAbsolute()) {
              System.err.println(
                  "Log4j: The path in '" + DLL_PATH_PROPERTY
                  + "' is not absolute: " + dllPath
                  + ". Falling back to library path resolution.");
              return null;
          }
          if (!dllFile.exists()) {
              System.err.println(
                  "Log4j: The file specified in '" + DLL_PATH_PROPERTY
                  + "' does not exist: " + dllPath
                  + ". Falling back to library path resolution.");
              return null;
          }
          return dllFile.getAbsolutePath();
      } catch (SecurityException e) {
          System.err.println(
              "Log4j: Security exception reading '" + DLL_PATH_PROPERTY
              + "'. Falling back to library path resolution.");
          return null;
      }
  }
}
