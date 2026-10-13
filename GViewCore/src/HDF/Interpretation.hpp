#pragma once

// I : (Gamma_n, tau_X) -> Omega. Total and two-stage: Aggregate (per verdict predicate and subject: max | min | mean |
// noisy_or) then Classify (ordered threshold conditions, first match, otherwise the fallback outcome). Across the subjects
// of the provenance tree of X the outcome with the smallest index in Omega wins (declaration order = priority); ties are
// broken by the subject closest to X, then by the lowest SubjectId (deterministic).

#include "AssertionBase.hpp"
#include "Signature.hpp"
#include "SubjectRegistry.hpp"

namespace GView::HDF
{
class ConstantPool;

struct Outcome {
    uint8 index{ 0 };
};

// Omega: ordered labels; "Inconclusive" is required (validated when the specification is loaded)
struct OutcomeSet {
    std::vector<std::string> labels;
    uint8 fallbackIndex{ 0 };

    std::optional<uint8> Find(std::string_view label) const;
    inline std::string_view Label(Outcome o) const
    {
        return o.index < labels.size() ? std::string_view(labels[o.index]) : std::string_view("?");
    }
};

enum class AggregateFunction : uint8 { Max = 0, Min, Mean, NoisyOr };
enum class ComparisonOperator : uint8 { GreaterEqual = 0, Greater, LessEqual, Less, Equal };
std::string_view AggregateFunctionName(AggregateFunction f);
std::optional<AggregateFunction> AggregateFunctionFromName(std::string_view name);
std::string_view ComparisonOperatorName(ComparisonOperator op);
std::optional<ComparisonOperator> ComparisonOperatorFromName(std::string_view name);

struct ClassificationCondition {
    uint8 outcome{ 0 };
    ComparisonOperator op{ ComparisonOperator::GreaterEqual };
    double value{ 0.0 };
};

// how one verdict predicate V(x, score) is interpreted
struct VerdictInterpretation {
    PredicateId predicate{ INVALID_PREDICATE_ID };
    AggregateFunction aggregate{ AggregateFunction::Max };
    std::vector<ClassificationCondition> conditions;
};

struct InterpretationDecision {
    Outcome outcome;
    bool fromVerdict{ false }; // false: no verdict assertion in the provenance tree of X (fallback outcome)
    PredicateId predicate{ INVALID_PREDICATE_ID };
    SubjectId subject{ INVALID_SUBJECT_ID }; // X': the subject whose verdict decided the outcome
    AggregateFunction aggregate{ AggregateFunction::Max };
    double score{ 0.0 };                                  // aggregated score of X' for predicate
    uint32 assertionCount{ 0 };                           // verdict assertions aggregated for (predicate, X')
    AssertionId verdictAssertion{ INVALID_ASSERTION_ID }; // the highest-scoring verdict assertion of (predicate, X') (its DT is shown)
    int32 conditionIndex{ -1 };                           // the matched condition (-1: fallback)
    std::vector<SubjectId> provenancePath;                // X' -> ... -> X
    uint32 subjectsConsidered{ 0 };
};

class Interpretation
{
  public:
    OutcomeSet outcomes;
    std::vector<VerdictInterpretation> verdicts;

    // Omega = { Inconclusive } when HDF.json has no interpretation section
    void SetDefault();
    static double Aggregate(AggregateFunction f, std::span<const double> scores);
    static bool Compare(ComparisonOperator op, double score, double value);
    // index of the first matching condition, or -1
    static int32 Classify(const VerdictInterpretation& vi, double score);
    const VerdictInterpretation* Find(PredicateId p) const;

    // I(Gamma, X) for the provenance tree of root (root and its descendants)
    InterpretationDecision Interpret(
          const AssertionBase& gamma, const Signature& signature, const ConstantPool& pool, const SubjectRegistry& registry, SubjectId root) const;
    // the verdict predicates of V without an explicit configuration use VerdictInterpretation{ p, Max, {} }
    std::vector<PredicateId> verdictPredicates;
};

} // namespace GView::HDF
