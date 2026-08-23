#pragma once

#include <future>
#include <string>
#include <vector>

#include "AnalysisEngine.hpp"
#include "GView.hpp"

namespace GView::Components::AnalysisEngine
{

struct SummaryResult {
    std::string narrative;
    std::vector<std::string> recommended_actions;
    bool success{ false };
};

class SummaryController
{
  public:
    [[nodiscard]] static std::string SerializeKnowledgeState(
          std::span<const Fact> facts,
          const SpecificationStorage<PredId, PredicateSpecification>& predicates,
          const std::vector<Suggestion>& suggestions,
          const RuleEngine& engine) noexcept;

    [[nodiscard]] static SummaryResult ParseAssistantResponse(std::string_view response) noexcept;

    [[nodiscard]] static SummaryResult RequestSummary(
          RuleEngine& engine,
          GView::CommonInterfaces::SmartAssistants::SmartAssistantPromptInterface* assistant) noexcept;
};

} // namespace GView::Components::AnalysisEngine
