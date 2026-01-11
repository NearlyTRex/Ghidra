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
/// \file multiequal_trace.cc
/// \brief MULTIEQUAL stack offset tracing implementation

#include "multiequal_trace.hh"
#include "decompiler_fixes.hh"
#include "decomp_dbg.hh"
#include <set>

namespace ghidra {

/// \brief Trace a varnode backward to determine its offset from the stack pointer
///
/// This function walks backward through the definition chain of a varnode to determine
/// if it derives from the stack pointer (ESP) and what constant offset it has.
/// Used to verify that all inputs to a MULTIEQUAL have the same ESP offset.
///
/// \param vn is the varnode to trace backward
/// \param spc is the stack address space
/// \param spInput is the stack pointer input varnode to match against
/// \param offset will receive the calculated offset from ESP
/// \param visited is a set of visited varnodes for cycle detection
/// \param depth is the current recursion depth
/// \return true if the varnode traces back to ESP with a constant offset
static bool traceStackOffsetBackward(Varnode *vn, AddrSpace *spc, Varnode *spInput,
                                      uintb &offset, set<Varnode *> &visited, int4 depth)
{
  if (depth > 16) {
    DECOMP_LOG("  traceBack[" << depth << "]: max depth exceeded");
    return false;
  }

  if (visited.find(vn) != visited.end()) {
    DECOMP_LOG("  traceBack[" << depth << "]: cycle detected");
    return false;
  }
  visited.insert(vn);

  // Check if this is the stack pointer input
  if (vn == spInput) {
    offset = 0;
    DECOMP_LOG("  traceBack[" << depth << "]: FOUND ESP input! offset=0");
    return true;
  }

  // Check if this varnode is in the stack space itself
  // Stack space varnodes ARE ESP-relative by definition - their offset IS the ESP offset
  if (vn->getSpace() == spc) {
    offset = vn->getOffset();
    DECOMP_LOG("  traceBack[" << depth << "]: FOUND stack space varnode! offset=0x" << std::hex << offset);
    return true;
  }

  // Check if this is an input varnode (but not ESP)
  if (vn->isInput()) {
    DECOMP_LOG("  traceBack[" << depth << "]: hit non-ESP input " << vn->getSpace()->getName()
                  << ":0x" << std::hex << vn->getOffset());
    return false;
  }

  // Must be written
  if (!vn->isWritten()) {
    DECOMP_LOG("  traceBack[" << depth << "]: not written, not input");
    return false;
  }

  PcodeOp *defop = vn->getDef();
  OpCode opc = defop->code();

  switch (opc) {
    case CPUI_COPY:
    case CPUI_INDIRECT:
    case CPUI_INT_AND:  // Stack alignment
    {
      // Offset unchanged, trace through input
      return traceStackOffsetBackward(defop->getIn(0), spc, spInput, offset, visited, depth + 1);
    }
    case CPUI_INT_ADD:
    {
      Varnode *in0 = defop->getIn(0);
      Varnode *in1 = defop->getIn(1);

      // One input should be constant
      if (in1->isConstant()) {
        uintb baseOffset;
        if (traceStackOffsetBackward(in0, spc, spInput, baseOffset, visited, depth + 1)) {
          offset = spc->wrapOffset(baseOffset + in1->getOffset());
          return true;
        }
      }
      else if (in0->isConstant()) {
        uintb baseOffset;
        if (traceStackOffsetBackward(in1, spc, spInput, baseOffset, visited, depth + 1)) {
          offset = spc->wrapOffset(baseOffset + in0->getOffset());
          return true;
        }
      }
      DECOMP_LOG("  traceBack[" << depth << "]: INT_ADD with no constant");
      return false;
    }
    case CPUI_INT_SUB:
    {
      Varnode *in0 = defop->getIn(0);
      Varnode *in1 = defop->getIn(1);

      // Second input should be constant (ESP - constant)
      if (in1->isConstant()) {
        uintb baseOffset;
        if (traceStackOffsetBackward(in0, spc, spInput, baseOffset, visited, depth + 1)) {
          offset = spc->wrapOffset(baseOffset - in1->getOffset());
          return true;
        }
      }
      DECOMP_LOG("  traceBack[" << depth << "]: INT_SUB with no constant");
      return false;
    }
    case CPUI_MULTIEQUAL:
    {
      // For nested MULTIEQUAL, check if all inputs have same offset
      uintb firstOffset = 0;
      bool firstSet = false;

      for (int4 i = 0; i < defop->numInput(); ++i) {
        set<Varnode *> branchVisited = visited;  // Fresh visited set per branch
        uintb branchOffset;

        if (!traceStackOffsetBackward(defop->getIn(i), spc, spInput, branchOffset, branchVisited, depth + 1)) {
          DECOMP_LOG("  traceBack[" << depth << "]: MULTIEQUAL input " << i << " failed");
          return false;
        }

        if (!firstSet) {
          firstOffset = branchOffset;
          firstSet = true;
        }
        else if (branchOffset != firstOffset) {
          DECOMP_LOG("  traceBack[" << depth << "]: MULTIEQUAL inputs have different offsets: 0x"
                        << std::hex << firstOffset << " vs 0x" << branchOffset);
          return false;
        }
      }

      offset = firstOffset;
      DECOMP_LOG("  traceBack[" << depth << "]: MULTIEQUAL all inputs same offset=0x" << std::hex << offset);
      return true;
    }
    default:
      DECOMP_LOG("  traceBack[" << depth << "]: unsupported opcode " << (int)opc);
      return false;
  }
}

bool checkMultiequalStackOffsets(PcodeOp *op, AddrSpace *spc, Varnode *spInput, uint8 funcAddr, uintb &commonOffset)
{
  // Check if the fix is enabled for this function
  if (!DecompilerFixes::hasFix(funcAddr, DFIX_MULTIEQUAL_STACK_TRACE)) {
    return false;  // Fix not enabled, use default behavior
  }

  DECOMP_LOG("checkMultiequalStackOffsets: checking MULTIEQUAL with " << op->numInput() << " inputs");

  uintb firstOffset = 0;
  bool firstSet = false;

  for (int4 i = 0; i < op->numInput(); ++i) {
    Varnode *inputVn = op->getIn(i);
    set<Varnode *> visited;
    uintb inputOffset;

    DECOMP_LOG("  checking input " << i << ": " << inputVn->getSpace()->getName()
                  << ":0x" << std::hex << inputVn->getOffset());

    if (!traceStackOffsetBackward(inputVn, spc, spInput, inputOffset, visited, 0)) {
      DECOMP_LOG("  input " << i << " FAILED to trace to ESP");
      return false;
    }

    DECOMP_LOG("  input " << i << " traced to ESP offset=0x" << std::hex << inputOffset);

    if (!firstSet) {
      firstOffset = inputOffset;
      firstSet = true;
    }
    else if (inputOffset != firstOffset) {
      DECOMP_LOG("  MULTIEQUAL inputs have DIFFERENT offsets: 0x" << std::hex << firstOffset
                    << " vs 0x" << inputOffset);
      return false;
    }
  }

  commonOffset = firstOffset;
  DECOMP_LOG("checkMultiequalStackOffsets: SUCCESS! All inputs have offset=0x" << std::hex << commonOffset);
  return true;
}

}
