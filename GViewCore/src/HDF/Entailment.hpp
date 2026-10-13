#pragma once

// Gamma |-_R gamma (assertion entailment, semi-naive Cl_R) and Gamma ||-_{R,A} beta (action entailment:
// Enabled / Completed / Selectable).

#include "DerivationIndex.hpp"
#include "GroundAction.hpp"
#include "Specification.hpp"

#include <algorithm>

namespace GView::HDF
{
// theta: rule-scoped variable -> constant (stack object)
struct Substitution {
    ConstantId binding[MAX_RULE_VARIABLES]{};
    uint16 boundMask{ 0 };

    inline bool IsBound(VariableIndex v) const
    {
        return (boundMask & (1u << v)) != 0;
    }
    inline void Bind(VariableIndex v, ConstantId c)
    {
        binding[v] = c;
        boundMask  = static_cast<uint16>(boundMask | (1u << v));
    }
    inline void Unbind(uint16 mask)
    {
        boundMask = static_cast<uint16>(boundMask & ~mask);
    }
    // theta(t)
    inline ConstantId Apply(Term t) const
    {
        return t.IsVariable() ? binding[t.Variable()] : t.Constant();
    }
};
static_assert(sizeof(Substitution) == 68);

class Join
{
  public:
    // extends theta so that theta(literal) = p(args); on failure theta is unchanged. newlyBound receives the bound variables.
    static inline bool MatchLiteral(std::span<const Term> literalTerms, std::span<const ConstantId> args, Substitution& theta, uint16& newlyBound)
    {
        newlyBound = 0;
        if (literalTerms.size() != args.size())
            return false;
        for (size_t i = 0; i < args.size(); i++) {
            const Term t = literalTerms[i];
            bool ok;
            if (t.IsConstant()) {
                ok = t.Constant() == args[i];
            } else if (theta.IsBound(t.Variable())) {
                ok = theta.binding[t.Variable()] == args[i];
            } else {
                theta.Bind(t.Variable(), args[i]);
                newlyBound = static_cast<uint16>(newlyBound | (1u << t.Variable()));
                ok         = true;
            }
            if (!ok) {
                theta.Unbind(newlyBound);
                newlyBound = 0;
                return false;
            }
        }
        return true;
    }

    // Enumerates every theta such that each body literal of rule matches an assertion of gamma.
    // fixedPosition (or INVALID_INDEX) is matched first with fixedAssertion (semi-naive delta position).
    // Candidate ids are restricted to < oldEnd for body positions before fixedPosition and to < end for the others.
    // visitor(const Substitution&, const AssertionId* premises /* in body order */) returns false to stop.
    // No allocation: explicit stack of at most MAX_BODY_LITERALS frames.
    template <typename Visitor>
    static bool Run(
          const AssertionBase& gamma,
          const Specification& h,
          const RuleBody& rule,
          uint32 fixedPosition,
          AssertionId fixedAssertion,
          uint32 oldEnd,
          uint32 end,
          Visitor&& visitor)
    {
        const uint32 n = rule.bodyCount;
        Substitution theta;
        AssertionId premises[MAX_BODY_LITERALS];
        const uint8* order = rule.fullOrder;
        uint32 start       = 0;
        if (fixedPosition != INVALID_INDEX) {
            order = rule.deltaOrder.data() + static_cast<size_t>(fixedPosition) * n;
            uint16 bound;
            if (!MatchLiteral(h.TermsOf(h.BodyLiteral(rule, fixedPosition)), gamma.Args(fixedAssertion), theta, bound))
                return true;
            premises[fixedPosition] = fixedAssertion;
            start                   = 1;
        }
        if (start == n)
            return visitor(static_cast<const Substitution&>(theta), static_cast<const AssertionId*>(premises));

        struct Frame {
            const AssertionId* candidates;
            uint32 next;
            uint32 limit;
            uint16 newlyBound;
        };
        Frame frames[MAX_BODY_LITERALS];
        auto initFrame = [&](uint32 depth) {
            const uint32 position = order[depth];
            const auto& literal   = h.BodyLiteral(rule, position);
            const auto lt         = h.TermsOf(literal);
            std::span<const AssertionId> list;
            if (!lt.empty() && (lt[0].IsConstant() || theta.IsBound(lt[0].Variable())))
                list = gamma.WithPredicateAndFirst(literal.predicate, theta.Apply(lt[0]));
            else
                list = gamma.WithPredicate(literal.predicate);
            const uint32 bound = (fixedPosition != INVALID_INDEX && position < fixedPosition) ? oldEnd : end;
            auto& f            = frames[depth];
            f.candidates       = list.data();
            f.next             = 0;
            f.limit            = static_cast<uint32>(std::lower_bound(list.begin(), list.end(), bound) - list.begin());
            f.newlyBound       = 0;
        };

        uint32 depth = start;
        initFrame(depth);
        while (true) {
            auto& f               = frames[depth];
            const uint32 position = order[depth];
            theta.Unbind(f.newlyBound);
            f.newlyBound  = 0;
            bool found    = false;
            const auto lt = h.TermsOf(h.BodyLiteral(rule, position));
            while (f.next < f.limit) {
                const AssertionId id = f.candidates[f.next++];
                if (MatchLiteral(lt, gamma.Args(id), theta, f.newlyBound)) {
                    premises[position] = id;
                    found              = true;
                    break;
                }
            }
            if (!found) {
                if (depth == start)
                    return true;
                depth--;
                continue;
            }
            if (depth + 1 == n) {
                if (!visitor(static_cast<const Substitution&>(theta), static_cast<const AssertionId*>(premises)))
                    return false;
                continue;
            }
            depth++;
            initFrame(depth);
        }
    }
};

struct ClosureResult {
    uint32 derived{ 0 };
    uint32 rounds{ 0 };
    bool limitReached{ false }; // MAX_DERIVED_PER_STEP: the closure is sound but incomplete
};

class AssertionEntailment
{
  public:
    // Cl_R by semi-naive evaluation of the delta [deltaBegin, |Gamma|). Derived assertions are recorded in dt with
    // kind Rule (premises = instantiated body) and the given transition index. fireGroundRules: also apply the rules with an
    // empty body (once per session). Derived heads are buffered and inserted at the end of each round, so no posting
    // list is modified while a join iterates over it.
    static ClosureResult Close(
          AssertionBase& gamma, const Specification& h, uint32 deltaBegin, DerivationIndex& dt, uint32 transition, uint32 maxDerived, bool fireGroundRules);

    // reference implementation (tests, benchmarks): naive fixpoint over all rules and all assertions (no derivations)
    static ClosureResult CloseNaive(AssertionBase& gamma, const Specification& h, uint32 maxDerived);
};

class ActionEntailment
{
  public:
    // Enabled(Gamma) computed incrementally: adds every beta enabled by a rule instance with at least one premise in
    // [deltaBegin, |Gamma|) (deltaBegin = 0: everything, including rules with an empty body). Since rules are positive,
    // Gamma subset Gamma' implies Enabled(Gamma) subset Enabled(Gamma'), so the set only grows.
    static void Enabled(const AssertionBase& gamma, const Specification& h, uint32 deltaBegin, GroundActionSet& enabled);
    // reference implementation: full join of every action rule
    static GroundActionSet EnabledFull(const AssertionBase& gamma, const Specification& h);
    // beta in Completed(Gamma) iff a is non-repeatable and Done_a(c1..ck) is in Gamma
    static bool IsCompleted(const AssertionBase& gamma, const Signature& signature, const GroundActionSet& enabled, GroundActionId beta);
    static std::vector<GroundActionId> Completed(const AssertionBase& gamma, const Signature& signature, const GroundActionSet& enabled);
    // Selectable(Gamma) = Enabled(Gamma) \ Completed(Gamma), ascending ids
    static std::vector<GroundActionId> Selectable(const AssertionBase& gamma, const Signature& signature, const GroundActionSet& enabled);
};

} // namespace GView::HDF
