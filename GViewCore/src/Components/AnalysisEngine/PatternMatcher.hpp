#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "AnalysisEngineData.hpp"
#include "KnowledgeBase.hpp"

namespace GView::Components::AnalysisEngine
{

using SubstitutionMap = std::unordered_map<std::string, Value>;

class PatternMatcher
{
  public:
    [[nodiscard]] static bool Holds(
          const ConjClause& clause,
          const Subject& subject,
          const KnowledgeBase& kb,
          std::vector<Reference<const Fact>>& matched_facts) noexcept;

    [[nodiscard]] static std::optional<SubstitutionMap> BuildSubstitutionFromFacts(
          std::span<Reference<const Fact>> facts) noexcept;

    [[nodiscard]] static bool ValuesEqual(const Value& a, const Value& b) noexcept;
};

} // namespace GView::Components::AnalysisEngine
