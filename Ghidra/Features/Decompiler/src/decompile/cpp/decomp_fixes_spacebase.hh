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
/// \file decomp_fixes_spacebase.hh
/// \brief Per-function fixes for spacebase/stack pointer tracking issues
///
/// This file contains fixes for BADSPACEBASE errors that can be enabled
/// on a per-function basis via the DecompilerFixes registry.

#ifndef __DECOMP_FIXES_SPACEBASE_HH__
#define __DECOMP_FIXES_SPACEBASE_HH__

#include "ruleaction.hh"

namespace ghidra {

/// \brief Try to force spacebase construction during type inference (DFIX_FORCE_SPACEBASE)
///
/// If the spacebase input varnode doesn't exist and DFIX_FORCE_SPACEBASE is enabled
/// for the function, attempt to construct it.
///
/// \param data is the function being analyzed
/// \param spcid is the address space (typically stack)
/// \param existingVn is the existing spacebase varnode (may be NULL)
/// \return the spacebase varnode (existing or newly constructed), or NULL if unavailable
Varnode *tryForceSpacebaseConstruction(Funcdata &data, AddrSpace *spcid, Varnode *existingVn);

/// \brief Try to recover spacebase in alias checker (DFIX_ALIAS_RECOVERY)
///
/// If the spacebase input varnode doesn't exist and DFIX_ALIAS_RECOVERY is enabled
/// for the function, attempt to construct it for alias analysis.
///
/// \param fd is the function being analyzed (const, but may be cast for recovery)
/// \param space is the address space
/// \param existingVn is the existing spacebase varnode (may be NULL)
/// \return the spacebase varnode (existing or newly constructed), or NULL if unavailable
Varnode *tryRecoverSpacebaseForAlias(const Funcdata *fd, AddrSpace *space, Varnode *existingVn);

/// \brief Propagate spacebase type when stack pointer is copied to another register
///
/// This rule handles the pattern:
///   MOV EAX, ESP
/// Where the stack pointer value is copied to a general-purpose register.
/// The destination register should inherit the spacebase typing so that
/// subsequent uses are properly recognized as stack references.
/// Only applies when DFIX_SPACEBASE_PROPAGATION is enabled for the function.
class RuleSpacebaseCopy : public Rule {
public:
  RuleSpacebaseCopy(const string &g) : Rule(g, 0, "spacebasecopy") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleSpacebaseCopy(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op, Funcdata &data);
};

}

#endif
