#pragma once

// Ground actions beta = <a>(c1..ck): a deduplicated set with flat argument storage. For each beta the first enabling
// rule instance is kept (the action rule and the assertions that matched its body).

#include "Term.hpp"

#include <span>

namespace GView::HDF
{
struct GroundAction {
    ActionId action{ INVALID_ACTION_ID };
    uint32 argOffset{ 0 };
    uint32 premiseOffset{ 0 };
    RuleId rule{ INVALID_RULE_ID }; // first action rule that enabled beta
    uint8 arity{ 0 };
    uint8 premiseCount{ 0 };
};
static_assert(sizeof(GroundAction) == 20);

class GroundActionSet
{
    std::vector<GroundAction> actions;
    std::vector<ConstantId> args;
    std::vector<AssertionId> premises;
    std::vector<uint64> hash;
    HashIndex index;

  public:
    struct AddResult {
        GroundActionId id;
        bool inserted;
    };
    AddResult Add(ActionId action, std::span<const ConstantId> values, RuleId rule, std::span<const AssertionId> enablingPremises);
    GroundActionId Find(ActionId action, std::span<const ConstantId> values) const; // INVALID_GROUND_ACTION_ID when absent
    inline bool Contains(ActionId action, std::span<const ConstantId> values) const
    {
        return Find(action, values) != INVALID_GROUND_ACTION_ID;
    }
    void Clear();

    inline uint32 Size() const
    {
        return static_cast<uint32>(actions.size());
    }
    inline const GroundAction& Get(GroundActionId id) const
    {
        return actions[id];
    }
    inline std::span<const ConstantId> Args(GroundActionId id) const
    {
        return { args.data() + actions[id].argOffset, actions[id].arity };
    }
    inline std::span<const AssertionId> Premises(GroundActionId id) const
    {
        return { premises.data() + actions[id].premiseOffset, actions[id].premiseCount };
    }
    inline size_t MemoryBytes() const
    {
        return actions.capacity() * sizeof(GroundAction) + args.capacity() * sizeof(ConstantId) + premises.capacity() * sizeof(AssertionId) +
               hash.capacity() * sizeof(uint64) + index.MemoryBytes();
    }
};

inline GroundActionSet::AddResult GroundActionSet::Add(
      ActionId action, std::span<const ConstantId> values, RuleId rule, std::span<const AssertionId> enablingPremises)
{
    const auto existing = Find(action, values);
    if (existing != INVALID_GROUND_ACTION_ID)
        return { existing, false };
    const auto id = static_cast<GroundActionId>(actions.size());
    GroundAction ga;
    ga.action        = action;
    ga.argOffset     = static_cast<uint32>(args.size());
    ga.arity         = static_cast<uint8>(values.size());
    ga.rule          = rule;
    ga.premiseOffset = static_cast<uint32>(premises.size());
    ga.premiseCount  = static_cast<uint8>(enablingPremises.size());
    args.insert(args.end(), values.begin(), values.end());
    premises.insert(premises.end(), enablingPremises.begin(), enablingPremises.end());
    actions.push_back(ga);
    const uint64 h = HashAtom(action, values.data(), static_cast<uint32>(values.size()));
    hash.push_back(h);
    index.Insert(h, id, [this](uint32 other) { return hash[other]; });
    return { id, true };
}

inline GroundActionId GroundActionSet::Find(ActionId action, std::span<const ConstantId> values) const
{
    const uint64 h = HashAtom(action, values.data(), static_cast<uint32>(values.size()));
    const auto id  = index.Find(h, [&](uint32 other) {
        if (hash[other] != h || actions[other].action != action || actions[other].arity != values.size())
            return false;
        const auto otherArgs = Args(other);
        for (size_t i = 0; i < values.size(); i++)
            if (otherArgs[i] != values[i])
                return false;
        return true;
    });
    return id == INVALID_INDEX ? INVALID_GROUND_ACTION_ID : id;
}

inline void GroundActionSet::Clear()
{
    actions.clear();
    args.clear();
    premises.clear();
    hash.clear();
    index.Clear();
}

} // namespace GView::HDF
