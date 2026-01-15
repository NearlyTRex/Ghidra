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
/// \file decomp_fixes_spacebase.cc
/// \brief Implementation of per-function spacebase fixes

#include "decomp_fixes_spacebase.hh"
#include "decomp_fixes.hh"
#include "funcdata.hh"

namespace ghidra {

Varnode *tryForceSpacebaseConstruction(Funcdata &data, AddrSpace *spcid, Varnode *existingVn)
{
  if (existingVn != (Varnode *)0)
    return existingVn;  // Already exists

  // Check if DFIX_FORCE_SPACEBASE is enabled for this function
  uint8 funcAddr = data.getAddress().getOffset();
  if (!DecompilerFixes::hasFix(funcAddr, DFIX_FORCE_SPACEBASE))
    return (Varnode *)0;  // Fix not enabled

  // Try to construct the spacebase input
  try {
    return data.constructSpacebaseInput(spcid);
  } catch (const LowlevelError &) {
    // Construction failed
    return (Varnode *)0;
  }
}

Varnode *tryRecoverSpacebaseForAlias(const Funcdata *fd, AddrSpace *space, Varnode *existingVn)
{
  if (existingVn != (Varnode *)0)
    return existingVn;  // Already exists

  // Check if DFIX_ALIAS_RECOVERY is enabled for this function
  uint8 funcAddr = fd->getAddress().getOffset();
  if (!DecompilerFixes::hasFix(funcAddr, DFIX_ALIAS_RECOVERY))
    return (Varnode *)0;  // Fix not enabled

  // Check if space has a spacebase register
  if (space->numSpacebase() == 0)
    return (Varnode *)0;

  // Try to construct the spacebase input
  try {
    // Cast away const - this is a recovery operation
    Funcdata *mutableFd = const_cast<Funcdata *>(fd);
    return mutableFd->constructSpacebaseInput(space);
  } catch (const LowlevelError &) {
    // Construction failed
    return (Varnode *)0;
  }
}

/// \class RuleSpacebaseCopy
/// \brief Propagate spacebase type when stack pointer is copied to another register

void RuleSpacebaseCopy::getOpList(vector<uint4> &oplist) const
{
  oplist.push_back(CPUI_COPY);
}

int4 RuleSpacebaseCopy::applyOp(PcodeOp *op, Funcdata &data)
{
  // Check if fix is enabled for this function
  uint8 funcAddr = data.getAddress().getOffset();
  if (!DecompilerFixes::hasFix(funcAddr, DFIX_SPACEBASE_PROPAGATION))
    return 0;

  Varnode *in = op->getIn(0);

  // Check if input has spacebase flag
  if (!in->isSpacebase()) return 0;

  Varnode *out = op->getOut();

  // Don't apply if output already has spacebase flag
  if (out->isSpacebase()) return 0;

  // Don't apply to constants or annotations
  if (out->isConstant() || out->isAnnotation()) return 0;

  // Get the architecture's stack space
  AddrSpace *stackSpace = data.getArch()->getStackSpace();
  if (stackSpace == (AddrSpace *)0) return 0;

  // Verify the input has a type
  Datatype *inType = in->getType();
  if (inType == (Datatype *)0) return 0;

  // Only proceed if input has a pointer type related to spacebase
  if (inType->getMetatype() != TYPE_PTR) return 0;

  Datatype *ptrTarget = ((TypePointer *)inType)->getPtrTo();
  if (ptrTarget->getMetatype() != TYPE_SPACEBASE) return 0;

  // Propagate the spacebase flag and type
  out->setFlags(Varnode::spacebase);
  out->updateType(inType, true, true);

  return 1;
}

}
