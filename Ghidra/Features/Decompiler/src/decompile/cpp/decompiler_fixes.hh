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
/// \file decompiler_fixes.hh
/// \brief Registry for enabling per-function decompiler fixes

#ifndef __DECOMPILER_FIXES_HH__
#define __DECOMPILER_FIXES_HH__

#include "types.h"

namespace ghidra {

/// \brief Flags for different decompiler fixes that can be enabled per-function
enum DecompilerFixFlags {
  DFIX_NONE = 0,
  DFIX_MULTIEQUAL_STACK_TRACE = 1 << 0,  ///< Trace MULTIEQUAL inputs for precise stack offsets
  // Future fixes can be added here:
  // DFIX_FUTURE_FIX_1 = 1 << 1,
  // DFIX_FUTURE_FIX_2 = 1 << 2,
};

/// \brief Registry for per-function decompiler fixes
///
/// This provides per-function control over various decompiler fixes and enhancements.
/// Functions can be registered with specific fix flags before decompilation, and
/// the decompiler checks this registry to decide which fixes to apply.
class DecompilerFixes {
public:
  /// Register a function address with specific fix flags
  /// \param addr is the function entry address
  /// \param flags is the bitmask of fixes to enable
  static void registerFixes(uint8 addr, uint4 flags);

  /// Add fix flags to an already registered address (or register if new)
  /// \param addr is the function entry address
  /// \param flags is the bitmask of fixes to add
  static void addFixes(uint8 addr, uint4 flags);

  /// Clear all registered addresses
  static void clearAll();

  /// Clear fixes for a specific address
  /// \param addr is the function entry address
  static void clearAddress(uint8 addr);

  /// Get the fix flags for a function
  /// \param addr is the function entry address
  /// \return the bitmask of enabled fixes (0 if not registered)
  static uint4 getFixes(uint8 addr);

  /// Check if a specific fix is enabled for a function
  /// \param addr is the function entry address
  /// \param flag is the fix flag to check
  /// \return true if the fix is enabled
  static bool hasFix(uint8 addr, DecompilerFixFlags flag);

  /// Check if any addresses are registered
  /// \return true if at least one address is registered
  static bool hasRegisteredAddresses();
};

}

#endif
