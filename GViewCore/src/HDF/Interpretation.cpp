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
    case ComparisonOperator::Equal:
        return "==";
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
    if (name == "==")
        return ComparisonOperator::Equal;
    return std::nullopt;
}

void Interpretation::SetDefault()
{
    outcomes.labels        = { "Inconclusive" };
    outcomes.fallbackIndex = 0;
    verdicts.clear();
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
    case ComparisonOperator::Equal:
        return score == value;
    }
    return false;
}

int32 Interpretation::Classify(const VerdictInterpretation& vi, double score)
{
    for (size_t i = 0; i < vi.conditions.size(); i++)
        if (Compare(vi.conditions[i].op, score, vi.conditions[i].value))
            return static_cast<int32>(i);
    return -1;
}

const VerdictInterpretation* Interpretation::Find(PredicateId p) const
{
    for (const auto& vi : verdicts)
        if (vi.predicate == p)
            return &vi;
    return nullptr;
}

InterpretationDecision Interpretation::Interpret(
      const AssertionBase& gamma, const Signature& signature, const ConstantPool& pool, const SubjectRegistry& registry, SubjectId root) const
{
    InterpretationDecision best;
    best.outcome.index = outcomes.fallbackIndex;
    if (!registry.IsValid(root))
        return best;

    std::vector<SubjectId> subjects;
    registry.Descendants(root, subjects);
    best.subjectsConsidered = static_cast<uint32>(subjects.size());

    // configured verdicts first (in declaration order), then the unconfigured verdict predicates
    std::vector<VerdictInterpretation> plan = verdicts;
    for (const auto p : verdictPredicates)
        if (!Find(p))
            plan.push_back({ p, AggregateFunction::Max, {} });

    bool found          = false;
    uint32 bestDistance = 0;
    std::vector<double> scores;
    for (const auto s : subjects) {
        const auto c = registry.Get(s).constant;
        if (c == INVALID_CONSTANT_ID)
            continue;
        const uint32 distance = registry.Get(s).depth - registry.Get(root).depth;
        for (const auto& vi : plan) {
            if (!signature.predicates.IsValid(vi.predicate))
                continue;
            const auto list = gamma.WithPredicateAndFirst(vi.predicate, c);
            if (list.empty())
                continue;
            scores.clear();
            AssertionId strongest = INVALID_ASSERTION_ID;
            double strongestScore = 0.0;
            for (const auto a : list) {
                const auto args = gamma.Args(a);
                if (args.size() != 2)
                    continue;
                const double score = pool.AsReal(args[1]);
                scores.push_back(score);
                if (strongest == INVALID_ASSERTION_ID || score > strongestScore) {
                    strongest      = a;
                    strongestScore = score;
                }
            }
            if (scores.empty())
                continue;
            const double aggregated = Aggregate(vi.aggregate, scores);
            const int32 condition   = Classify(vi, aggregated);
            const uint8 outcome     = condition >= 0 ? vi.conditions[condition].outcome : outcomes.fallbackIndex;
            // smallest outcome index, then closest subject, then lowest SubjectId (subjects are visited in pre-order,
            // so compare the id explicitly), then the first verdict predicate in plan order
            const bool better = !found || outcome < best.outcome.index || (outcome == best.outcome.index && distance < bestDistance) ||
                                (outcome == best.outcome.index && distance == bestDistance && s < best.subject);
            if (!better)
                continue;
            found                 = true;
            bestDistance          = distance;
            best.outcome.index    = outcome;
            best.fromVerdict      = true;
            best.predicate        = vi.predicate;
            best.subject          = s;
            best.aggregate        = vi.aggregate;
            best.score            = aggregated;
            best.assertionCount   = static_cast<uint32>(scores.size());
            best.verdictAssertion = strongest;
            best.conditionIndex   = condition;
        }
    }
    if (found)
        best.provenancePath = registry.ProvenancePath(best.subject, root);
    return best;
}

} // namespace GView::HDF
