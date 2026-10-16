#pragma once

// I : (Gamma_n, tau_X) -> Omega with Omega = Omega_c u { Inconclusive }. The instantiation declares the conclusive labels
// Omega_c, each with a condition = conjunction of clauses over the combined verdict scores of one subject:
//   presence  exists V(Y, c): c OP t        absence  not exists V(Y, c): c OP t        OP in { >=, >, <=, < }
// Absence is evaluated by the interpretation on Gamma_n (it is not negation in the calculus). Three stages:
//   1. Combine:   per (V, Y) the scores of the V(Y, c) assertions are combined (max | min | mean | noisy_or, default max)
//   2. Evaluate:  I_subj(Y): exactly one label holds -> that label; none -> Inconclusive (no label satisfied);
//                 several -> Inconclusive (conflict). Labels are evaluated in declaration order, no priority is applied.
//   3. Aggregate: over subjects(X) = { X } u descendants of X along ExtractedFrom, through a replaceable hook. Default: a
//                 propagating label (Malicious) holds for X when it holds for any Y; a non-propagating label (Benign) holds
//                 for X when I_subj(X) is that label and no propagating label holds for any Y; exactly-one rule again.
// Inconclusive is added by the framework: it has no condition and carries a structured reason; an instantiation may only
// give it a display alias. Nothing here is an assertion rule: the interpretation reads Gamma_n, it never writes it.

#include "AssertionBase.hpp"
#include "Signature.hpp"
#include "SubjectRegistry.hpp"

namespace GView::HDF
{
class ConstantPool;
class Interpretation;

struct Outcome {
    uint8 index{ 0 };
};

// Omega = Omega_c u { Inconclusive }: the conclusive labels in declaration order, then "Inconclusive" (appended by the
// framework when the specification is loaded; it can not be declared)
struct OutcomeSet {
    std::vector<std::string> labels;
    uint8 inconclusiveIndex{ 0 };  // == |Omega_c|; Outcome{ inconclusiveIndex } is Inconclusive
    std::string inconclusiveAlias; // optional display name (e.g. "Unknown"); the semantics never change

    // finds a declared label or "Inconclusive" (not the alias)
    std::optional<uint8> Find(std::string_view label) const;
    inline std::string_view Label(Outcome o) const
    {
        if (o.index == inconclusiveIndex && !inconclusiveAlias.empty())
            return inconclusiveAlias;
        return o.index < labels.size() ? std::string_view(labels[o.index]) : std::string_view("?");
    }
    inline bool IsConclusive(Outcome o) const
    {
        return o.index < inconclusiveIndex;
    }
    inline Outcome Inconclusive() const
    {
        return { inconclusiveIndex };
    }
    inline uint32 ConclusiveCount() const
    {
        return inconclusiveIndex;
    }
};

enum class AggregateFunction : uint8 { Max = 0, Min, Mean, NoisyOr };
enum class ComparisonOperator : uint8 { GreaterEqual = 0, Greater, LessEqual, Less };
std::string_view AggregateFunctionName(AggregateFunction f);
std::optional<AggregateFunction> AggregateFunctionFromName(std::string_view name);
std::string_view ComparisonOperatorName(ComparisonOperator op);
std::optional<ComparisonOperator> ComparisonOperatorFromName(std::string_view name);

enum class ClauseKind : uint8 { Present = 0, Absent };
struct Clause {
    ClauseKind kind{ ClauseKind::Present };
    PredicateId predicate{ INVALID_PREDICATE_ID };
    ComparisonOperator op{ ComparisonOperator::GreaterEqual };
    double threshold{ 0.0 };
};

// when a decision for a label is final (settled): Immediate = as soon as the label is decided; Exhaustion = only when
// nothing is selectable any more (absence clauses read the current knowledge: a selectable action may still disclose
// the evidence an absence clause excludes)
enum class SettleMode : uint8 { Immediate = 0, Exhaustion };
std::string_view SettleModeName(SettleMode mode);
std::optional<SettleMode> SettleModeFromName(std::string_view name);

// the condition of one conclusive label: a conjunction of clauses; propagate = the label holds for X when it holds for
// any subject of the provenance tree of X (maliciousness propagates upward, benignity does not)
struct LabelCondition {
    uint8 outcome{ 0 };
    bool propagate{ false };
    SettleMode settle{ SettleMode::Immediate };
    std::vector<Clause> clauses;
};

// how the scores of several V(Y, c_i) are combined before the interpretation reads them (default: max)
struct ScoreCombination {
    PredicateId predicate{ INVALID_PREDICATE_ID };
    AggregateFunction aggregate{ AggregateFunction::Max };
};

enum class SubjectAggregationKind : uint8 { Default = 0, Strict };
std::string_view SubjectAggregationKindName(SubjectAggregationKind kind);
std::optional<SubjectAggregationKind> SubjectAggregationKindFromName(std::string_view name);

// ---- results ------------------------------------------------------------------------------------------------------

// the combined score of (V, Y); only produced when at least one V(Y, c) is in Gamma
struct CombinedScore {
    PredicateId predicate{ INVALID_PREDICATE_ID };
    double score{ 0.0 };
    uint32 count{ 0 };                             // V(Y, c) assertions combined
    AssertionId strongest{ INVALID_ASSERTION_ID }; // the highest raw score (its DT is shown)
    AggregateFunction aggregate{ AggregateFunction::Max };
};

struct ClauseEvaluation {
    uint32 clause{ 0 };
    bool holds{ false };
    bool present{ false };                       // a V(Y, c) assertion exists
    double score{ 0.0 };                         // the combined score (when present)
    AssertionId witness{ INVALID_ASSERTION_ID }; // the strongest V(Y, c) (INVALID when absent)
};

struct LabelEvaluation {
    uint8 outcome{ 0 };
    bool holds{ false };
    int32 firstFailedClause{ -1 }; // -1: every clause holds
    std::vector<ClauseEvaluation> clauses;
};

enum class InconclusiveReason : uint8 { None = 0, NoLabelSatisfied, Conflict, NotEvaluated };
std::string_view InconclusiveReasonName(InconclusiveReason reason);

// I_subj(Y)
struct SubjectDecision {
    SubjectId subject{ INVALID_SUBJECT_ID };
    Outcome outcome;
    InconclusiveReason reason{ InconclusiveReason::NotEvaluated };
    std::vector<LabelEvaluation> labels; // one per label condition, in declaration order
    std::vector<CombinedScore> scores;   // one per verdict predicate with at least one assertion about Y

    const CombinedScore* FindScore(PredicateId p) const;
    const LabelEvaluation* FindLabel(uint8 outcome) const;
};

// I(Gamma_n, tau_X)
struct InterpretationDecision {
    Outcome outcome;
    InconclusiveReason reason{ InconclusiveReason::NotEvaluated };
    bool conclusive{ false };                   // outcome != Inconclusive
    bool settled{ false };                      // conclusive and (settle == Immediate or nothing is selectable)
    SettleMode settle{ SettleMode::Immediate }; // the settle mode of the decided label (when conclusive)
    uint32 selectableCount{ 0 };                // |Selectable(Gamma_i)| the decision was evaluated with
    SubjectId input{ INVALID_SUBJECT_ID };      // X
    SubjectId deciding{ INVALID_SUBJECT_ID };   // the Y whose per-subject outcome decided (== input when not propagated)
    std::vector<SubjectId> provenancePath;      // deciding -> ... -> input
    std::vector<SubjectDecision> subjects;      // X first, then its descendants in pre-order
    std::vector<uint8> conflictingLabels;       // the labels in conflict (reason == Conflict)

    const SubjectDecision* FindSubject(SubjectId s) const;
};

// the replaceable aggregation over subjects(X); subjects[0] is I_subj(X), the rest are the descendants in pre-order. It
// fills outcome, reason, conclusive, deciding and conflictingLabels of out (Interpret sets the rest).
struct SubjectAggregationInterface {
    virtual void Aggregate(
          const Interpretation& interpretation,
          const SubjectRegistry& registry,
          SubjectId input,
          std::span<const SubjectDecision> subjects,
          InterpretationDecision& out) const = 0;
    virtual ~SubjectAggregationInterface()   = default;
};

// propagating labels hold for X when they hold for any Y (the first Y in pre-order decides); non-propagating labels hold
// for X when I_subj(X) is that label and no propagating label holds; then the exactly-one rule
class DefaultSubjectAggregation : public SubjectAggregationInterface
{
  protected:
    // strict: a non-propagating label is also blocked when any Y != X is Inconclusive because of a conflict
    void Run(const Interpretation& interpretation, std::span<const SubjectDecision> subjects, InterpretationDecision& out, bool strict) const;

  public:
    void Aggregate(
          const Interpretation& interpretation,
          const SubjectRegistry& registry,
          SubjectId input,
          std::span<const SubjectDecision> subjects,
          InterpretationDecision& out) const override;
};

class StrictSubjectAggregation : public DefaultSubjectAggregation
{
  public:
    void Aggregate(
          const Interpretation& interpretation,
          const SubjectRegistry& registry,
          SubjectId input,
          std::span<const SubjectDecision> subjects,
          InterpretationDecision& out) const override;
};

class Interpretation
{
  public:
    OutcomeSet outcomes;
    std::vector<PredicateId> verdictPredicates; // V: the only predicates the interpretation reads
    std::vector<ScoreCombination> combinations; // explicit entries; Combination(p) is max when absent
    std::vector<LabelCondition> labels;         // at most one condition per conclusive outcome, in declaration order
    SubjectAggregationKind aggregation{ SubjectAggregationKind::Default };

    // Omega = { Inconclusive }, no labels (HDF.json without an interpretation section)
    void SetDefault();
    static double Aggregate(AggregateFunction f, std::span<const double> scores);
    static bool Compare(ComparisonOperator op, double score, double value);
    AggregateFunction Combination(PredicateId p) const;
    const LabelCondition* ConditionOf(uint8 outcome) const;
    // the hook selected by `aggregation`
    const SubjectAggregationInterface& DefaultHook() const;

    // I_subj(Y)
    SubjectDecision InterpretSubject(const AssertionBase& gamma, const Signature& signature, const ConstantPool& pool, SubjectId y, ConstantId yConstant) const;
    // I(Gamma, X) over the provenance tree of x (x and its descendants); hook == nullptr: the hook of `aggregation`.
    // selectableCount = |Selectable(Gamma_i)| of the session (it only decides whether an Exhaustion label is settled)
    InterpretationDecision Interpret(
          const AssertionBase& gamma,
          const Signature& signature,
          const ConstantPool& pool,
          const SubjectRegistry& registry,
          SubjectId x,
          uint32 selectableCount,
          const SubjectAggregationInterface* hook = nullptr) const;
    // Inconclusive / NotEvaluated for x (the decision of a session that has not been interpreted yet)
    InterpretationDecision NotEvaluated(SubjectId x) const;
};

} // namespace GView::HDF
