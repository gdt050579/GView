#include "Interpretation.hpp"
#include "ConstantPool.hpp"

#include <algorithm>

namespace GView::HDF
{
std::optional<uint8> OutcomeSet::Find(std::string_view label) const
{
    for (size_t i = 0; i < labels.size(); i++)
        if (labels[i] == label)
            return static_cast<uint8>(i);
    return std::nullopt;
}

std::string_view AggregateFunctionName(AggregateFunction f)
{
    switch (f) {
    case AggregateFunction::Max:
        return "max";
    case AggregateFunction::Min:
        return "min";
    case AggregateFunction::Mean:
        return "mean";
    case AggregateFunction::NoisyOr:
        return "noisy_or";
    }
    return "?";
}

std::optional<AggregateFunction> AggregateFunctionFromName(std::string_view name)
{
    if (name == "max")
        return AggregateFunction::Max;
    if (name == "min")
        return AggregateFunction::Min;
    if (name == "mean")
        return AggregateFunction::Mean;
    if (name == "noisy_or")
        return AggregateFunction::NoisyOr;
    return std::nullopt;
}

std::string_view ComparisonOperatorName(ComparisonOperator op)
{
    switch (op) {
    case ComparisonOperator::GreaterEqual:
        return ">=";
    case ComparisonOperator::Greater:
        return ">";
    case ComparisonOperator::LessEqual:
        return "<=";
    case ComparisonOperator::Less:
        return "<";
    }
    return "?";
}

std::optional<ComparisonOperator> ComparisonOperatorFromName(std::string_view name)
{
    if (name == ">=")
        return ComparisonOperator::GreaterEqual;
    if (name == ">")
        return ComparisonOperator::Greater;
    if (name == "<=")
        return ComparisonOperator::LessEqual;
    if (name == "<")
        return ComparisonOperator::Less;
    return std::nullopt;
}

std::string_view SubjectAggregationKindName(SubjectAggregationKind kind)
{
    switch (kind) {
    case SubjectAggregationKind::Default:
        return "default";
    case SubjectAggregationKind::Strict:
        return "strict";
    }
    return "?";
}

std::optional<SubjectAggregationKind> SubjectAggregationKindFromName(std::string_view name)
{
    if (name == "default")
        return SubjectAggregationKind::Default;
    if (name == "strict")
        return SubjectAggregationKind::Strict;
    return std::nullopt;
}

std::string_view SettleModeName(SettleMode mode)
{
    switch (mode) {
    case SettleMode::Immediate:
        return "immediate";
    case SettleMode::Exhaustion:
        return "exhaustion";
    }
    return "?";
}

std::optional<SettleMode> SettleModeFromName(std::string_view name)
{
    if (name == "immediate")
        return SettleMode::Immediate;
    if (name == "exhaustion")
        return SettleMode::Exhaustion;
    return std::nullopt;
}

std::string_view InconclusiveReasonName(InconclusiveReason reason)
{
    switch (reason) {
    case InconclusiveReason::None:
        return "none";
    case InconclusiveReason::NoLabelSatisfied:
        return "no label satisfied";
    case InconclusiveReason::Conflict:
        return "conflict";
    case InconclusiveReason::NotEvaluated:
        return "not evaluated";
    }
    return "?";
}

const CombinedScore* SubjectDecision::FindScore(PredicateId p) const
{
    for (const auto& s : scores)
        if (s.predicate == p)
            return &s;
    return nullptr;
}

const LabelEvaluation* SubjectDecision::FindLabel(uint8 outcome) const
{
    for (const auto& l : labels)
        if (l.outcome == outcome)
            return &l;
    return nullptr;
}

const SubjectDecision* InterpretationDecision::FindSubject(SubjectId s) const
{
    for (const auto& d : subjects)
        if (d.subject == s)
            return &d;
    return nullptr;
}

// ---- aggregation over subjects ----------------------------------------------------------------------------------------

void DefaultSubjectAggregation::Run(
      const Interpretation& interpretation, std::span<const SubjectDecision> subjects, InterpretationDecision& out, bool strict) const
{
    const auto& omega = interpretation.outcomes;
    out.outcome       = omega.Inconclusive();
    out.conclusive    = false;
    out.reason        = InconclusiveReason::NotEvaluated;
    out.conflictingLabels.clear();
    if (subjects.empty())
        return;
    const auto& x = subjects[0];
    out.deciding  = x.subject;

    // holder[o]: the subject for which the conclusive label o holds at the input level (INVALID: o does not hold)
    std::vector<SubjectId> holder(omega.ConclusiveCount(), INVALID_SUBJECT_ID);
    bool anyPropagating = false;
    for (const auto& condition : interpretation.labels) {
        if (!condition.propagate || condition.outcome >= holder.size())
            continue;
        for (const auto& y : subjects)
            if (y.outcome.index == condition.outcome) { // the first Y in pre-order (creation order) decides
                holder[condition.outcome] = y.subject;
                anyPropagating            = true;
                break;
            }
    }
    const SubjectDecision* conflicted = nullptr;
    if (strict)
        for (size_t i = 1; i < subjects.size() && !conflicted; i++)
            if (subjects[i].reason == InconclusiveReason::Conflict)
                conflicted = &subjects[i];
    const SubjectDecision* blockedBy = nullptr;
    for (const auto& condition : interpretation.labels) {
        if (condition.propagate || condition.outcome >= holder.size() || x.outcome.index != condition.outcome || anyPropagating)
            continue;
        if (conflicted) {
            blockedBy = conflicted;
            continue;
        }
        holder[condition.outcome] = x.subject;
    }

    // exactly-one rule at the input level
    std::vector<uint8> holding;
    for (size_t o = 0; o < holder.size(); o++)
        if (holder[o] != INVALID_SUBJECT_ID)
            holding.push_back(static_cast<uint8>(o));
    if (holding.size() == 1) {
        out.outcome    = { holding[0] };
        out.conclusive = true;
        out.reason     = InconclusiveReason::None;
        out.deciding   = holder[holding[0]];
        return;
    }
    if (holding.size() > 1) {
        out.reason            = InconclusiveReason::Conflict;
        out.conflictingLabels = std::move(holding);
        return;
    }
    const auto& source = blockedBy ? *blockedBy : x;
    out.deciding       = source.subject;
    out.reason         = blockedBy ? InconclusiveReason::Conflict : x.reason;
    if (out.reason == InconclusiveReason::None || out.reason == InconclusiveReason::NotEvaluated)
        out.reason = InconclusiveReason::NoLabelSatisfied;
    if (out.reason == InconclusiveReason::Conflict)
        for (const auto& l : source.labels)
            if (l.holds)
                out.conflictingLabels.push_back(l.outcome);
}

void DefaultSubjectAggregation::Aggregate(
      const Interpretation& interpretation,
      [[maybe_unused]] const SubjectRegistry& registry,
      [[maybe_unused]] SubjectId input,
      std::span<const SubjectDecision> subjects,
      InterpretationDecision& out) const
{
    Run(interpretation, subjects, out, false);
}

void StrictSubjectAggregation::Aggregate(
      const Interpretation& interpretation,
      [[maybe_unused]] const SubjectRegistry& registry,
      [[maybe_unused]] SubjectId input,
      std::span<const SubjectDecision> subjects,
      InterpretationDecision& out) const
{
    Run(interpretation, subjects, out, true);
}

// ---- Interpretation ---------------------------------------------------------------------------------------------------

void Interpretation::SetDefault()
{
    outcomes.labels            = { "Inconclusive" };
    outcomes.inconclusiveIndex = 0;
    outcomes.inconclusiveAlias.clear();
    combinations.clear();
    labels.clear();
    aggregation = SubjectAggregationKind::Default;
}

double Interpretation::Aggregate(AggregateFunction f, std::span<const double> scores)
{
    if (scores.empty())
        return 0.0;
    switch (f) {
    case AggregateFunction::Max:
        return *std::max_element(scores.begin(), scores.end());
    case AggregateFunction::Min:
        return *std::min_element(scores.begin(), scores.end());
    case AggregateFunction::Mean: {
        double sum = 0.0;
        for (const auto s : scores)
            sum += s;
        return sum / static_cast<double>(scores.size());
    }
    case AggregateFunction::NoisyOr: {
        // 1 - prod(1 - s_i), scores clamped to [0, 1]
        double product = 1.0;
        for (const auto s : scores)
            product *= 1.0 - std::clamp(s, 0.0, 1.0);
        return 1.0 - product;
    }
    }
    return 0.0;
}

bool Interpretation::Compare(ComparisonOperator op, double score, double value)
{
    switch (op) {
    case ComparisonOperator::GreaterEqual:
        return score >= value;
    case ComparisonOperator::Greater:
        return score > value;
    case ComparisonOperator::LessEqual:
        return score <= value;
    case ComparisonOperator::Less:
        return score < value;
    }
    return false;
}

AggregateFunction Interpretation::Combination(PredicateId p) const
{
    for (const auto& c : combinations)
        if (c.predicate == p)
            return c.aggregate;
    return AggregateFunction::Max;
}

const LabelCondition* Interpretation::ConditionOf(uint8 outcome) const
{
    for (const auto& l : labels)
        if (l.outcome == outcome)
            return &l;
    return nullptr;
}

const SubjectAggregationInterface& Interpretation::DefaultHook() const
{
    static const DefaultSubjectAggregation defaultAggregation;
    static const StrictSubjectAggregation strictAggregation;
    if (aggregation == SubjectAggregationKind::Strict)
        return strictAggregation;
    return defaultAggregation;
}

SubjectDecision Interpretation::InterpretSubject(
      const AssertionBase& gamma, const Signature& signature, const ConstantPool& pool, SubjectId y, ConstantId yConstant) const
{
    SubjectDecision d;
    d.subject = y;
    d.outcome = outcomes.Inconclusive();

    // 1. combine the scores of every (V, Y)
    if (yConstant != INVALID_CONSTANT_ID) {
        std::vector<double> scores;
        for (const auto p : verdictPredicates) {
            if (!signature.predicates.IsValid(p))
                continue;
            scores.clear();
            CombinedScore combined;
            combined.predicate    = p;
            combined.aggregate    = Combination(p);
            double strongestScore = 0.0;
            for (const auto a : gamma.WithPredicateAndFirst(p, yConstant)) {
                const auto args = gamma.Args(a);
                if (args.size() != 2)
                    continue;
                const double score = pool.AsReal(args[1]);
                scores.push_back(score);
                if (combined.strongest == INVALID_ASSERTION_ID || score > strongestScore) {
                    combined.strongest = a;
                    strongestScore     = score;
                }
            }
            if (scores.empty())
                continue;
            combined.count = static_cast<uint32>(scores.size());
            combined.score = Aggregate(combined.aggregate, scores);
            d.scores.push_back(combined);
        }
    }

    // 2. evaluate every label condition on the combined scores (declaration order, no priority)
    uint32 holding = 0;
    uint8 winner   = outcomes.inconclusiveIndex;
    d.labels.reserve(labels.size());
    for (const auto& condition : labels) {
        LabelEvaluation le;
        le.outcome = condition.outcome;
        le.holds   = true;
        le.clauses.reserve(condition.clauses.size());
        for (uint32 i = 0; i < condition.clauses.size(); i++) {
            const auto& clause = condition.clauses[i];
            const auto* score  = d.FindScore(clause.predicate);
            ClauseEvaluation ce;
            ce.clause  = i;
            ce.present = score != nullptr;
            if (score) {
                ce.score   = score->score;
                ce.witness = score->strongest;
            }
            const bool satisfied = score && Compare(clause.op, score->score, clause.threshold);
            ce.holds             = clause.kind == ClauseKind::Present ? satisfied : !satisfied;
            if (!ce.holds && le.firstFailedClause < 0)
                le.firstFailedClause = static_cast<int32>(i);
            le.holds = le.holds && ce.holds;
            le.clauses.push_back(ce);
        }
        if (le.holds) {
            holding++;
            winner = le.outcome;
        }
        d.labels.push_back(std::move(le));
    }

    // 3. exactly one holding label
    if (holding == 1) {
        d.outcome = { winner };
        d.reason  = InconclusiveReason::None;
    } else {
        d.reason = holding == 0 ? InconclusiveReason::NoLabelSatisfied : InconclusiveReason::Conflict;
    }
    return d;
}

InterpretationDecision Interpretation::NotEvaluated(SubjectId x) const
{
    InterpretationDecision d;
    d.outcome  = outcomes.Inconclusive();
    d.reason   = InconclusiveReason::NotEvaluated;
    d.input    = x;
    d.deciding = x;
    return d;
}

InterpretationDecision Interpretation::Interpret(
      const AssertionBase& gamma,
      const Signature& signature,
      const ConstantPool& pool,
      const SubjectRegistry& registry,
      SubjectId x,
      uint32 selectableCount,
      const SubjectAggregationInterface* hook) const
{
    auto out            = NotEvaluated(x);
    out.selectableCount = selectableCount;
    if (!registry.IsValid(x))
        return out;

    std::vector<SubjectId> ids;
    registry.Descendants(x, ids);
    std::vector<SubjectDecision> subjects;
    subjects.reserve(ids.size());
    for (const auto id : ids)
        subjects.push_back(InterpretSubject(gamma, signature, pool, id, registry.Get(id).constant));

    (hook ? *hook : DefaultHook()).Aggregate(*this, registry, x, subjects, out);

    // a replaceable hook can not break the invariants: Inconclusive <=> a reason, deciding in subjects(X)
    out.input = x;
    if (out.outcome.index > outcomes.inconclusiveIndex)
        out.outcome = outcomes.Inconclusive();
    out.conclusive = outcomes.IsConclusive(out.outcome);
    if (out.conclusive)
        out.reason = InconclusiveReason::None;
    else if (out.reason == InconclusiveReason::None || out.reason == InconclusiveReason::NotEvaluated)
        out.reason = InconclusiveReason::NoLabelSatisfied;
    // settled: the decided label settles immediately, or at exhaustion and nothing is selectable (a label without a
    // condition, possible only through a custom hook, settles immediately)
    if (out.conclusive) {
        const auto* condition = ConditionOf(out.outcome.index);
        out.settle            = condition ? condition->settle : SettleMode::Immediate;
        out.settled           = out.settle == SettleMode::Immediate || selectableCount == 0;
    }
    out.provenancePath = registry.ProvenancePath(out.deciding, x);
    if (out.provenancePath.empty()) {
        out.deciding       = x;
        out.provenancePath = { x };
    }
    out.subjects = std::move(subjects);
    return out;
}

} // namespace GView::HDF
