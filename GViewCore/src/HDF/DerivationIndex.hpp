#pragma once

// DT(gamma): one flat DerivationRecord per assertion (the first derivation wins: set semantics), premises stored as a
// range of one shared vector. Premises always have smaller ids than the derived assertion, so the tree is acyclic and
// materialized on demand by DerivationTree::Build.

#include "AssertionBase.hpp"

namespace GView::HDF
{
enum class DerivationKind : uint8 {
    InitialExtraction = 0, // disclosed by Init_T(X) (PopulateWindow of the subject's window)
    Action            = 1, // in Gamma_beta (disclosed by the execution of beta); premises = enabling premises of beta
    Observation       = 2, // disclosed by a tool operation that is not an HDF action (e.g. a plugin command)
    Rule              = 3, // derived by an assertion rule; premises = the instantiated body
    Completion        = 4, // Done_a(c1..ck) added after a successful execution (D_beta)
};
std::string_view DerivationKindName(DerivationKind kind);

struct DerivationRecord {
    DerivationKind kind{ DerivationKind::InitialExtraction };
    uint8 premiseCount{ 0 };
    uint16 reserved{ 0 };
    uint32 ruleOrAction{ INVALID_INDEX }; // RuleId (Rule) / GroundActionId (Action, Completion) / label StringId (Observation)
    uint32 premiseOffset{ 0 };            // into DerivationIndex::premises
    uint32 transition{ INVALID_INDEX };   // index of the DisclosureTransition that added the assertion
};
static_assert(sizeof(DerivationRecord) == 16, "DerivationRecord must stay 16 bytes");

class DerivationIndex
{
    std::vector<DerivationRecord> records; // per AssertionId
    std::vector<AssertionId> premises;

  public:
    // premise ranges can be shared between records (e.g. every assertion of one Gamma_beta)
    uint32 StorePremises(std::span<const AssertionId> ids);
    // id must be the next assertion id (records are appended in id order)
    bool Record(AssertionId id, DerivationKind kind, uint32 ruleOrAction, uint32 premiseOffset, uint8 premiseCount, uint32 transition);
    inline uint32 Size() const
    {
        return static_cast<uint32>(records.size());
    }
    inline const DerivationRecord& Get(AssertionId id) const
    {
        return records[id];
    }
    inline std::span<const AssertionId> Premises(const DerivationRecord& record) const
    {
        return { premises.data() + record.premiseOffset, record.premiseCount };
    }
    inline size_t MemoryBytes() const
    {
        return records.capacity() * sizeof(DerivationRecord) + premises.capacity() * sizeof(AssertionId);
    }
};

struct DerivationTreeNode {
    AssertionId assertion;
    uint32 depth;
    uint32 parent; // index in the node vector (INVALID_INDEX for the root)
    bool repeated; // already expanded earlier in the tree (shared premise): its premises are not repeated
};

// a materialized derivation tree, pre-order (a node is followed by its premises). Derivations form a DAG (a premise can
// support several assertions); with shareSubtrees every assertion is expanded once and later occurrences are marked.
struct DerivationTree {
    std::vector<DerivationTreeNode> nodes;
    bool truncated{ false }; // maxDepth / maxNodes reached

    static DerivationTree Build(const DerivationIndex& index, AssertionId root, uint32 maxDepth = 64, uint32 maxNodes = 4096, bool shareSubtrees = true);
};

} // namespace GView::HDF
