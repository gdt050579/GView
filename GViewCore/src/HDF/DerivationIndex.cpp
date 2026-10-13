#include "DerivationIndex.hpp"

#include <unordered_set>

namespace GView::HDF
{
std::string_view DerivationKindName(DerivationKind kind)
{
    switch (kind) {
    case DerivationKind::InitialExtraction:
        return "initial extraction";
    case DerivationKind::Action:
        return "action";
    case DerivationKind::Observation:
        return "observation";
    case DerivationKind::Rule:
        return "rule";
    case DerivationKind::Completion:
        return "completion";
    }
    return "?";
}

uint32 DerivationIndex::StorePremises(std::span<const AssertionId> ids)
{
    const auto offset = static_cast<uint32>(premises.size());
    premises.insert(premises.end(), ids.begin(), ids.end());
    return offset;
}

bool DerivationIndex::Record(AssertionId id, DerivationKind kind, uint32 ruleOrAction, uint32 premiseOffset, uint8 premiseCount, uint32 transition)
{
    if (id != records.size())
        return false; // derivations are recorded once, in insertion order (first derivation wins)
    // invariant: premises precede the derived assertion (DT is acyclic)
    for (uint32 i = 0; i < premiseCount; i++)
        if (premiseOffset + i >= premises.size() || premises[premiseOffset + i] >= id)
            return false;
    DerivationRecord record;
    record.kind          = kind;
    record.premiseCount  = premiseCount;
    record.ruleOrAction  = ruleOrAction;
    record.premiseOffset = premiseOffset;
    record.transition    = transition;
    records.push_back(record);
    return true;
}

DerivationTree DerivationTree::Build(const DerivationIndex& index, AssertionId root, uint32 maxDepth, uint32 maxNodes, bool shareSubtrees)
{
    DerivationTree tree;
    if (root >= index.Size())
        return tree;
    struct Pending {
        AssertionId assertion;
        uint32 depth;
        uint32 parent;
    };
    std::vector<Pending> stack{ { root, 0, INVALID_INDEX } };
    std::unordered_set<AssertionId> expanded;
    while (!stack.empty()) {
        const auto current = stack.back();
        stack.pop_back();
        if (tree.nodes.size() >= maxNodes) {
            tree.truncated = true;
            break;
        }
        const auto nodeIndex = static_cast<uint32>(tree.nodes.size());
        const auto& record   = index.Get(current.assertion);
        const auto premises  = index.Premises(record);
        const bool repeated  = shareSubtrees && !premises.empty() && !expanded.insert(current.assertion).second;
        tree.nodes.push_back({ current.assertion, current.depth, current.parent, repeated });
        if (premises.empty() || repeated)
            continue;
        if (current.depth + 1 > maxDepth) {
            tree.truncated = true;
            continue;
        }
        for (auto it = premises.rbegin(); it != premises.rend(); ++it)
            if (*it < current.assertion) // always true (checked by Record); keeps the walk finite even on corrupted data
                stack.push_back({ *it, current.depth + 1, nodeIndex });
    }
    return tree;
}

} // namespace GView::HDF
