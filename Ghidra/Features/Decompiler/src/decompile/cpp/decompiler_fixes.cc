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
/// \file decompiler_fixes.cc
/// \brief Implementation of per-function decompiler fixes registry

#include "decompiler_fixes.hh"
#include <map>

namespace ghidra {

/// Static map of function addresses to their enabled fix flags
static std::map<uint8, uint4> fixRegistry;

void DecompilerFixes::registerFixes(uint8 addr, uint4 flags)
{
  fixRegistry[addr] = flags;
}

void DecompilerFixes::addFixes(uint8 addr, uint4 flags)
{
  fixRegistry[addr] |= flags;
}

void DecompilerFixes::clearAll()
{
  fixRegistry.clear();
}

void DecompilerFixes::clearAddress(uint8 addr)
{
  fixRegistry.erase(addr);
}

uint4 DecompilerFixes::getFixes(uint8 addr)
{
  auto it = fixRegistry.find(addr);
  if (it != fixRegistry.end()) {
    return it->second;
  }
  return DFIX_NONE;
}

bool DecompilerFixes::hasFix(uint8 addr, DecompilerFixFlags flag)
{
  return (getFixes(addr) & flag) != 0;
}

bool DecompilerFixes::hasRegisteredAddresses()
{
  return !fixRegistry.empty();
}

}
