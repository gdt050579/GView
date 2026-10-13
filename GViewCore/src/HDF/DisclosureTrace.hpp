#pragma once

// The disclosure trace tau_X = (Gamma_0 ->beta_0 Gamma_1 ->beta_1 ... Gamma_n). Knowledge states are prefixes of the
// append-only AssertionBase, so a transition only stores index ranges of the log:
//   [fromCount, disclosedBegin)          - empty (kept for the formal reading: Gamma_i = [0, fromCount))
//   [disclosedBegin, disclosedEnd)       - Gamma_beta (what the tool disclosed while executing beta)
//   completionAssertion                  - D_beta = { Done_a(c1..ck) } (successful non-repeatable actions only)
//   [disclosedEnd(+1), toCount)          - what Cl_R derived; Gamma_i+1 = [0, toCount)

#include "Term.hpp"

#include <vector>

namespace GView::HDF
{
struct KnowledgeState {
    uint32 assertionCount{ 0 }; // Gamma_i = AssertionBase[0, assertionCount)
};

enum class TransitionKind : uint8 {
    InitialExtraction = 0, // Init_T(X): what the type plugin disclosed when the subject was opened
    Action            = 1, // the execution of a selected ground action beta_i
    Observation       = 2, // facts produced by a tool operation that is not an HDF action (plugin command, Disclose)
};
std::string_view TransitionKindName(TransitionKind kind);

struct DisclosureTransition {
    TransitionKind kind{ TransitionKind::InitialExtraction };
    ActionStatus status{ ActionStatus::Success };
    uint8 closureIncomplete{ 0 }; // MAX_DERIVED_PER_STEP was reached while closing this transition
    uint8 reserved{ 0 };
    SubjectId subject{ INVALID_SUBJECT_ID };           // the subject of an initial extraction / observation, beta's subject otherwise
    GroundActionId action{ INVALID_GROUND_ACTION_ID }; // beta_i (id in the session's GroundActionSet)
    StringId label{ EMPTY_STRING_ID };                 // observation label
    uint32 fromCount{ 0 };
    uint32 disclosedBegin{ 0 };
    uint32 disclosedEnd{ 0 };
    AssertionId completionAssertion{ INVALID_ASSERTION_ID };
    uint32 toCount{ 0 };
    int64 timestamp{ 0 }; // milliseconds since the epoch
};
static_assert(sizeof(DisclosureTransition) == 48, "DisclosureTransition layout changed");

class DisclosureTrace
{
  public:
    std::vector<DisclosureTransition> transitions;

    inline uint32 Size() const
    {
        return static_cast<uint32>(transitions.size());
    }
    // number of executed ground actions (the n of beta_0 .. beta_n-1)
    uint32 ActionCount() const;
    // the step index i of transition t (only meaningful for kind == Action)
    uint32 StepIndex(uint32 transition) const;
};

} // namespace GView::HDF
