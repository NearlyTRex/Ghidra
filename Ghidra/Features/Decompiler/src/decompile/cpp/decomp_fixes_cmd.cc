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
/// \file decomp_fixes_cmd.cc
/// \brief Implementation of GhidraCommands for per-function decompiler fixes

#include "ghidra_process.hh"
#include "decomp_fixes.hh"

namespace ghidra {

/// Load parameters for SetDecompilerFixes - reads flags and address list
/// Does not require an Architecture - operates on global registry
void SetDecompilerFixes::loadParameters(void)

{
  // Read and ignore arch id (for protocol compatibility)
  int4 type = ArchitectureGhidra::readToAnyBurst(sin);
  if (type != 14)
    throw JavaError("alignment", "Expecting arch id start");
  int4 ignoredId;
  sin >> dec >> ignoredId;
  type = ArchitectureGhidra::readToAnyBurst(sin);
  if (type != 15)
    throw JavaError("alignment", "Expecting arch id end");

  // Read flags value
  type = ArchitectureGhidra::readToAnyBurst(sin);
  if (type != 14)
    throw JavaError("alignment", "Expecting flags start");
  sin >> dec >> flags;
  type = ArchitectureGhidra::readToAnyBurst(sin);
  if (type != 15)
    throw JavaError("alignment", "Expecting flags end");

  // Read address count
  type = ArchitectureGhidra::readToAnyBurst(sin);
  if (type != 14)
    throw JavaError("alignment", "Expecting address count start");
  int4 count;
  sin >> dec >> count;
  type = ArchitectureGhidra::readToAnyBurst(sin);
  if (type != 15)
    throw JavaError("alignment", "Expecting address count end");

  // Read addresses
  addresses.resize(count);
  for (int4 i = 0; i < count; ++i) {
    type = ArchitectureGhidra::readToAnyBurst(sin);
    if (type != 14)
      throw JavaError("alignment", "Expecting address start");
    sin >> hex >> addresses[i];
    type = ArchitectureGhidra::readToAnyBurst(sin);
    if (type != 15)
      throw JavaError("alignment", "Expecting address end");
  }
}

void SetDecompilerFixes::rawAction(void)

{
  for (size_t i = 0; i < addresses.size(); ++i) {
    DecompilerFixes::addFixes(addresses[i], flags);
  }
  res = true;
}

void SetDecompilerFixes::sendResult(void)

{
  sout.write("\000\000\001\016", 4);
  if (res)
    sout << 't';
  else
    sout << 'f';
  sout.write("\000\000\001\017", 4);
  sout.write("\000\000\001\007", 4);  // End of command response
  sout.flush();
}

/// Load parameters for ClearDecompilerFixes - reads and ignores arch id
void ClearDecompilerFixes::loadParameters(void)

{
  // Read and ignore arch id (for protocol compatibility)
  int4 type = ArchitectureGhidra::readToAnyBurst(sin);
  if (type != 14)
    throw JavaError("alignment", "Expecting arch id start");
  int4 ignoredId;
  sin >> dec >> ignoredId;
  type = ArchitectureGhidra::readToAnyBurst(sin);
  if (type != 15)
    throw JavaError("alignment", "Expecting arch id end");
}

void ClearDecompilerFixes::rawAction(void)

{
  DecompilerFixes::clearAll();
  res = true;
}

void ClearDecompilerFixes::sendResult(void)

{
  sout.write("\000\000\001\016", 4);
  if (res)
    sout << 't';
  else
    sout << 'f';
  sout.write("\000\000\001\017", 4);
  sout.write("\000\000\001\007", 4);  // End of command response
  sout.flush();
}

}
