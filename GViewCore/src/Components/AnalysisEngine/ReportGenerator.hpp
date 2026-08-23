#pragma once

#include <string>

#include "KnowledgeBase.hpp"

namespace GView::Components::AnalysisEngine
{

class ReportGenerator
{
  public:
    [[nodiscard]] static std::string BuildExplanation(
          const FactKey& key,
          const DerivationIndex& index,
          const SpecificationStorage<PredId, PredicateSpecification>& predicates,
          uint32 depth = 0) noexcept;

    [[nodiscard]] static std::string GenerateReport(
          const Subject& subject,
          std::span<const StateTransition> trace,
          std::span<const Fact> facts,
          const FactKey& verdict_key,
          const DerivationIndex& derivations,
          const SpecificationStorage<PredId, PredicateSpecification>& predicates) noexcept;
};

} // namespace GView::Components::AnalysisEngine
