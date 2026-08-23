#include "ReportGenerator.hpp"

#include <format>
#include <sstream>

namespace GView::Components::AnalysisEngine
{
namespace
{
    [[nodiscard]] std::string PredicateName(
          PredId id, const SpecificationStorage<PredId, PredicateSpecification>& predicates) noexcept
    {
        const auto it = predicates.id_to_specification.find(id);
        if (it != predicates.id_to_specification.end())
            return it->second.name;
        return "unknown";
    }
} // namespace

std::string ReportGenerator::BuildExplanation(
      const FactKey& key,
      const DerivationIndex& index,
      const SpecificationStorage<PredId, PredicateSpecification>& predicates,
      uint32 depth) noexcept
{
    const auto it = index.find(key);
    if (it == index.end())
        return std::format("{} (initial extraction)", PredicateName(key.pred, predicates));

    const auto& node = it->second;
    std::ostringstream oss;
    const std::string indent(depth * 2, ' ');
    const auto pred_name = PredicateName(key.pred, predicates);

    switch (node->source_type) {
    case DerivationSourceType::Rule:
        oss << indent << std::format("Derived [{}] via rule {}\n", pred_name, node->source_rule_id);
        break;
    case DerivationSourceType::Action:
        oss << indent << std::format("Action {} revealed [{}]\n", node->source_action_id, pred_name);
        break;
    case DerivationSourceType::InitialExtraction:
        oss << indent << std::format("Initial extraction: [{}]\n", pred_name);
        break;
    }

    for (const auto& dep : node->dependencies) {
        if (dep)
            oss << BuildExplanation(dep->derived_key, index, predicates, depth + 1);
    }
    return oss.str();
}

std::string ReportGenerator::GenerateReport(
      const Subject& subject,
      std::span<const StateTransition> trace,
      std::span<const Fact> facts,
      const FactKey& verdict_key,
      const DerivationIndex& derivations,
      const SpecificationStorage<PredId, PredicateSpecification>& predicates) noexcept
{
    std::ostringstream oss;
    oss << "# HDF Analysis Report\n\n";
    oss << std::format("## Subject (kind={}, id={})\n\n", static_cast<uint32>(subject.kind), subject.value);
    oss << "## Verdict\n";
    oss << PredicateName(verdict_key.pred, predicates) << "\n\n";
    oss << "## Derivation (DT)\n";
    oss << BuildExplanation(verdict_key, derivations, predicates) << "\n";
    oss << "## Disclosure Trace\n";
    for (size_t i = 0; i < trace.size(); ++i) {
        oss << std::format("### Step {}\n", i + 1);
        oss << std::format("- Facts added: {}\n", trace[i].new_fact_indices.size());
        for (const auto idx : trace[i].new_fact_indices) {
            if (idx < facts.size()) {
                const auto pred_it = predicates.id_to_specification.find(facts[idx].atom.pred);
                if (pred_it != predicates.id_to_specification.end())
                    oss << "  - " << FormatFactMessage(facts[idx], pred_it->second) << '\n';
            }
        }
    }
    return oss.str();
}

} // namespace GView::Components::AnalysisEngine
