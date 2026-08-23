#pragma once

#include <string>
#include <vector>

#include "AnalysisEngineData.hpp"
#include "KnowledgeBase.hpp"

namespace GView::Components::AnalysisEngine
{

struct FormattedTransitionEntry {
    std::string formatted_action;
    std::vector<std::string> formatted_facts;
};

class ActionViewProvider
{
  public:
    [[nodiscard]] static std::vector<FormattedTransitionEntry> FormatTrace(
          std::span<const StateTransition> trace,
          std::span<const Fact> facts,
          const SpecificationStorage<PredId, PredicateSpecification>& predicates,
          const SpecificationStorage<ActId, PredicateSpecification>& actions) noexcept;
};

} // namespace GView::Components::AnalysisEngine
