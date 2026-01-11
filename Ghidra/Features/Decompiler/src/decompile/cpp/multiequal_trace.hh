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
/// \file multiequal_trace.hh
/// \brief MULTIEQUAL stack offset tracing for heritage analysis

#ifndef __MULTIEQUAL_TRACE_HH__
#define __MULTIEQUAL_TRACE_HH__

#include "op.hh"
#include "space.hh"
#include "varnode.hh"

namespace ghidra {

/// \brief Check if all MULTIEQUAL inputs have the same stack offset
///
/// Given a MULTIEQUAL operation, trace backward through all its inputs to determine
/// if they all derive from ESP with the same constant offset. If so, the MULTIEQUAL
/// output has a definite stack offset and doesn't need to be marked as uncertain.
///
/// This function first checks if the DFIX_MULTIEQUAL_STACK_TRACE fix is enabled
/// for the given function address via the DecompilerFixes registry.
///
/// \param op is the MULTIEQUAL operation
/// \param spc is the stack address space
/// \param spInput is the stack pointer input varnode
/// \param funcAddr is the function entry address (for fix registry lookup)
/// \param commonOffset will receive the common offset if all inputs match
/// \return true if all inputs have the same definite offset from ESP
extern bool checkMultiequalStackOffsets(PcodeOp *op, AddrSpace *spc, Varnode *spInput, uint8 funcAddr, uintb &commonOffset);

}

#endif
