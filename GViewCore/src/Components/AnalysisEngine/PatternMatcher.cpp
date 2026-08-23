#include "PatternMatcher.hpp"

namespace GView::Components::AnalysisEngine
{
bool PatternMatcher::ValuesEqual(const Value& a, const Value& b) noexcept
{
    if (a.index() != b.index())
        return false;
    return std::visit(
          [&b](auto&& lhs) -> bool {
              using T = std::decay_t<decltype(lhs)>;
              return lhs == std::get<T>(b);
          },
          a);
}

std::optional<SubstitutionMap> PatternMatcher::BuildSubstitutionFromFacts(std::span<Reference<const Fact>> facts) noexcept
{
    SubstitutionMap subst;
    subst.reserve(8);
    for (auto& fact_ref : facts) {
        if (!fact_ref.IsValid())
            continue;
        const Fact& fact = fact_ref;
        for (const auto& arg : fact.atom.args) {
            auto it = subst.find(arg.name);
            if (it == subst.end()) {
                subst.emplace(arg.name, arg.value);
            } else if (!ValuesEqual(it->second, arg.value)) {
                return std::nullopt;
            }
        }
    }
    return subst;
}

bool PatternMatcher::Holds(
      const ConjClause& clause,
      const Subject& subject,
      const KnowledgeBase& kb,
      std::vector<Reference<const Fact>>& matched_facts) noexcept
{
    matched_facts.clear();
    matched_facts.reserve(clause.all_of.size());
    const auto t_now = now();

    for (const auto& literal : clause.all_of) {
        auto optional_fact = kb.GetFact(literal.pred, subject);
        const bool present = optional_fact.has_value();
        if (!literal.negated) {
            if (!present)
                return false;
            if (clause.window.count() > 0) {
                auto last = kb.LastTime(literal.pred, subject);
                if (!last.has_value())
                    return false;
                const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(t_now - *last);
                if (age > clause.window)
                    return false;
            }
        } else {
            if (present)
                return false;
        }
        if (present)
            matched_facts.emplace_back(optional_fact.value());
    }

    // Theory Note: Cross-literal argument unification is only enforced when all body
    // literals share named args; distinct subjects per literal are not supported.
    if (matched_facts.size() > 1) {
        if (!BuildSubstitutionFromFacts(std::span<Reference<const Fact>>(matched_facts)).has_value())
            return false;
    }
    return true;
}

} // namespace GView::Components::AnalysisEngine
