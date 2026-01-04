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
/// Enable by defining DECOMP_DEBUG_ENABLED before including this header.
///
/// Environment variables:
///   DECOMP_TARGET_FUNC - Hex address to filter logging (e.g., "0x447f20")
///                        Set to 0 or unset to apply to all functions
///
/// Log output is written to /tmp/decomp_debug.log

#ifndef __DECOMP_DBG_HH__
#define __DECOMP_DBG_HH__

#define DECOMP_DEBUG_ENABLED

#include <cstdlib>
#include <cstdint>

/// Get target function address from environment variable
inline uint64_t getDecompTargetFunc() {
  static uint64_t target = 0;
  static bool initialized = false;
  if (!initialized) {
    const char* env = std::getenv("DECOMP_TARGET_FUNC");
    if (env) {
      target = std::strtoull(env, nullptr, 16);
    }
    initialized = true;
  }
  return target;
}

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

/// Check if function address matches target (or target is 0 for all functions)
#define DECOMP_IS_TARGET_FUNC(addr) \
  (getDecompTargetFunc() == 0 || (addr) == getDecompTargetFunc())

/// Thread-local flag for current function target status
inline bool& decompIsCurrentTarget() {
  static thread_local bool isTarget = false;
  return isTarget;
}

#define DECOMP_SET_TARGET(addr) (decompIsCurrentTarget() = DECOMP_IS_TARGET_FUNC(addr))
#define DECOMP_IS_CURRENT_TARGET() (decompIsCurrentTarget())

#else

#define DECOMP_LOG(msg) ((void)0)
#define DECOMP_IS_TARGET_FUNC(addr) (getDecompTargetFunc() == 0 || (addr) == getDecompTargetFunc())
#define DECOMP_SET_TARGET(addr) ((void)0)
#define DECOMP_IS_CURRENT_TARGET() (getDecompTargetFunc() == 0)

#endif

#endif
