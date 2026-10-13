#include "Entailment.hpp"

namespace GView::HDF
{
namespace
{
    // buffered rule heads of one semi-naive round (deduplicated, verified against Gamma before buffering)
    class PendingHeads
    {
      public:
        struct Entry {
            PredicateId predicate;
            uint32 argOffset;
            uint32 premiseOffset;
            RuleId rule;
            uint8 arity;
            uint8 premiseCount;
        };
        std::vector<Entry> entries;
        std::vector<ConstantId> args;
        std::vector<AssertionId> premises;

      private:
        std::vector<uint64> hashes;
        HashIndex index;

      public:
        std::span<const ConstantId> Args(const Entry& e) const
        {
            return { args.data() + e.argOffset, e.arity };
        }
        // false when the head is already buffered
        bool Add(PredicateId p, std::span<const ConstantId> values, RuleId rule, std::span<const AssertionId> body)
        {
            const uint64 h = HashAtom(p, values.data(), static_cast<uint32>(values.size()));
            const auto id  = index.Find(h, [&](uint32 other) {
                const auto& e = entries[other];
                if (hashes[other] != h || e.predicate != p || e.arity != values.size())
                    return false;
                return std::equal(values.begin(), values.end(), args.begin() + e.argOffset);
            });
            if (id != INVALID_INDEX)
                return false;
            Entry e{ p,    static_cast<uint32>(args.size()),  static_cast<uint32>(premises.size()),
                     rule, static_cast<uint8>(values.size()), static_cast<uint8>(body.size()) };
            args.insert(args.end(), values.begin(), values.end());
            premises.insert(premises.end(), body.begin(), body.end());
            entries.push_back(e);
            hashes.push_back(h);
            index.Insert(h, static_cast<uint32>(entries.size() - 1), [this](uint32 other) { return hashes[other]; });
            return true;
        }
        void Clear()
        {
            entries.clear();
            args.clear();
            premises.clear();
            hashes.clear();
            index.Clear();
        }
    };

    // theta(head) for an assertion rule; returns false if the head would be non-ground (impossible for safe rules)
    inline bool InstantiateHead(const Specification& h, const AssertionRule& rule, const Substitution& theta, ConstantId* out)
    {
        const auto ht = h.TermsOf(rule.head);
        for (size_t i = 0; i < ht.size(); i++) {
            if (ht[i].IsVariable() && !theta.IsBound(ht[i].Variable()))
                return false;
            out[i] = theta.Apply(ht[i]);
        }
        return true;
    }
} // namespace

ClosureResult AssertionEntailment::Close(
      AssertionBase& gamma, const Specification& h, uint32 deltaBegin, DerivationIndex& dt, uint32 transition, uint32 maxDerived, bool fireGroundRules)
{
    ClosureResult result;
    PendingHeads pending;
    ConstantId head[MAX_ARITY];
    bool stop = false;

    auto collect = [&](RuleId r) {
        return [&, r](const Substitution& theta, const AssertionId* premises) {
            const auto& rule = h.assertionRules[r];
            if (!InstantiateHead(h, rule, theta, head))
                return true;
            const std::span<const ConstantId> values(head, rule.head.arity);
            if (gamma.Contains(rule.head.predicate, values))
                return true;
            if (pending.Add(rule.head.predicate, values, r, std::span<const AssertionId>(premises, rule.bodyCount)) &&
                result.derived + pending.entries.size() >= maxDerived) {
                stop = true;
                return false; // MAX_DERIVED_PER_STEP reached
            }
            return true;
        };
    };

    if (fireGroundRules) {
        for (RuleId r = 0; r < h.assertionRules.size() && !stop; r++)
            if (h.assertionRules[r].bodyCount == 0)
                Join::Run(gamma, h, h.assertionRules[r], INVALID_INDEX, INVALID_ASSERTION_ID, 0, 0, collect(r));
    }

    uint32 roundBegin = deltaBegin;
    while (true) {
        const uint32 end = gamma.Size();
        for (AssertionId a = roundBegin; a < end && !stop; a++) {
            for (const auto& occurrence : h.AssertionRulesUsing(gamma.Predicate(a))) {
                const auto& rule = h.assertionRules[occurrence.rule];
                if (!Join::Run(gamma, h, rule, occurrence.position, a, roundBegin, end, collect(occurrence.rule)))
                    break;
            }
        }
        result.rounds++;
        if (pending.entries.empty())
            break;
        const uint32 nextBegin = gamma.Size();
        for (const auto& e : pending.entries) {
            const auto inserted = gamma.Insert(e.predicate, pending.Args(e));
            if (!inserted.inserted)
                continue; // only possible when the 32-bit id space is exhausted
            const auto offset = dt.StorePremises(std::span<const AssertionId>(pending.premises.data() + e.premiseOffset, e.premiseCount));
            dt.Record(inserted.id, DerivationKind::Rule, e.rule, offset, e.premiseCount, transition);
            result.derived++;
        }
        pending.Clear();
        if (stop) {
            result.limitReached = true;
            break;
        }
        roundBegin = nextBegin;
        if (gamma.Size() == nextBegin)
            break;
    }
    return result;
}

ClosureResult AssertionEntailment::CloseNaive(AssertionBase& gamma, const Specification& h, uint32 maxDerived)
{
    ClosureResult result;
    ConstantId head[MAX_ARITY];
    std::vector<std::pair<PredicateId, std::vector<ConstantId>>> found;
    bool changed = true;
    while (changed && result.derived < maxDerived) {
        changed = false;
        result.rounds++;
        found.clear();
        const uint32 end = gamma.Size();
        for (const auto& rule : h.assertionRules) {
            Join::Run(gamma, h, rule, INVALID_INDEX, INVALID_ASSERTION_ID, end, end, [&](const Substitution& theta, const AssertionId*) {
                if (InstantiateHead(h, rule, theta, head))
                    found.emplace_back(rule.head.predicate, std::vector<ConstantId>(head, head + rule.head.arity));
                return true;
            });
        }
        for (const auto& [p, values] : found) {
            if (gamma.Insert(p, values).inserted) {
                changed = true;
                result.derived++;
            }
        }
    }
    result.limitReached = changed;
    return result;
}

void ActionEntailment::Enabled(const AssertionBase& gamma, const Specification& h, uint32 deltaBegin, GroundActionSet& enabled)
{
    ConstantId values[MAX_ARITY];
    const uint32 end = gamma.Size();
    auto collect     = [&](RuleId r) {
        return [&, r](const Substitution& theta, const AssertionId* premises) {
            const auto& rule = h.actionRules[r];
            const auto ht    = h.TermsOf(rule.head);
            for (size_t i = 0; i < ht.size(); i++) {
                if (ht[i].IsVariable() && !theta.IsBound(ht[i].Variable()))
                    return true;
                values[i] = theta.Apply(ht[i]);
            }
            enabled.Add(rule.head.action, std::span<const ConstantId>(values, rule.head.arity), r, std::span<const AssertionId>(premises, rule.bodyCount));
            return true;
        };
    };
    if (deltaBegin == 0) {
        for (RuleId r = 0; r < h.actionRules.size(); r++)
            if (h.actionRules[r].bodyCount == 0)
                Join::Run(gamma, h, h.actionRules[r], INVALID_INDEX, INVALID_ASSERTION_ID, 0, 0, collect(r));
    }
    for (AssertionId a = deltaBegin; a < end; a++)
        for (const auto& occurrence : h.ActionRulesUsing(gamma.Predicate(a)))
            Join::Run(gamma, h, h.actionRules[occurrence.rule], occurrence.position, a, deltaBegin, end, collect(occurrence.rule));
}

GroundActionSet ActionEntailment::EnabledFull(const AssertionBase& gamma, const Specification& h)
{
    GroundActionSet result;
    ConstantId values[MAX_ARITY];
    const uint32 end = gamma.Size();
    for (RuleId r = 0; r < h.actionRules.size(); r++) {
        const auto& rule = h.actionRules[r];
        Join::Run(gamma, h, rule, INVALID_INDEX, INVALID_ASSERTION_ID, end, end, [&](const Substitution& theta, const AssertionId* premises) {
            const auto ht = h.TermsOf(rule.head);
            for (size_t i = 0; i < ht.size(); i++)
                values[i] = theta.Apply(ht[i]);
            result.Add(rule.head.action, std::span<const ConstantId>(values, rule.head.arity), r, std::span<const AssertionId>(premises, rule.bodyCount));
            return true;
        });
    }
    return result;
}

bool ActionEntailment::IsCompleted(const AssertionBase& gamma, const Signature& signature, const GroundActionSet& enabled, GroundActionId beta)
{
    const auto& ga     = enabled.Get(beta);
    const auto& action = signature.actions.Get(ga.action);
    if (action.repeatable || action.donePredicate == INVALID_PREDICATE_ID)
        return false;
    return gamma.Contains(action.donePredicate, enabled.Args(beta));
}

std::vector<GroundActionId> ActionEntailment::Completed(const AssertionBase& gamma, const Signature& signature, const GroundActionSet& enabled)
{
    std::vector<GroundActionId> result;
    for (GroundActionId b = 0; b < enabled.Size(); b++)
        if (IsCompleted(gamma, signature, enabled, b))
            result.push_back(b);
    return result;
}

std::vector<GroundActionId> ActionEntailment::Selectable(const AssertionBase& gamma, const Signature& signature, const GroundActionSet& enabled)
{
    std::vector<GroundActionId> result;
    result.reserve(enabled.Size());
    for (GroundActionId b = 0; b < enabled.Size(); b++)
        if (!IsCompleted(gamma, signature, enabled, b))
            result.push_back(b);
    return result;
}

} // namespace GView::HDF
