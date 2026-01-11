/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file decomp_dbg.hh
/// \brief Simple unbuffered file logging for decompiler debugging
///
/// This header provides debug logging macros for the decompiler.
/// Define DECOMP_DEBUG_ENABLED to enable logging to /tmp/decomp_debug.log

#ifndef __DECOMP_DBG_HH__
#define __DECOMP_DBG_HH__

// Uncomment to enable debug logging
// #define DECOMP_DEBUG_ENABLED

#ifdef DECOMP_DEBUG_ENABLED

#include <fstream>
#include <sstream>

/// Get unbuffered log file stream
inline std::ofstream& getDecompLog() {
  static std::ofstream logfile("/tmp/decomp_debug.log", std::ios::app);
  logfile << std::unitbuf;  // Unbuffered for immediate writes
  return logfile;
}

#define DECOMP_LOG(msg) do { \
  std::ostringstream _oss; \
  _oss << msg; \
  getDecompLog() << _oss.str() << "\n"; \
} while(0)

#else

#define DECOMP_LOG(msg) ((void)0)

#endif

#endif
