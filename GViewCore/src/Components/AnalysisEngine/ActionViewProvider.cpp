#include "ActionViewProvider.hpp"

namespace GView::Components::AnalysisEngine
{
std::vector<FormattedTransitionEntry> ActionViewProvider::FormatTrace(
      std::span<const StateTransition> trace,
      std::span<const Fact> facts,
      const SpecificationStorage<PredId, PredicateSpecification>& predicates,
      const SpecificationStorage<ActId, PredicateSpecification>& actions) noexcept
{
    std::vector<FormattedTransitionEntry> result;
    result.reserve(trace.size());

    for (const auto& tr : trace) {
        FormattedTransitionEntry entry;
        if (tr.action_executed.has_value()) {
            const auto act_it = actions.id_to_specification.find(tr.action_executed->action_id);
            if (act_it != actions.id_to_specification.end()) {
                entry.formatted_action = act_it->second.explanation;
            } else {
                entry.formatted_action = "Action";
            }
        } else {
            entry.formatted_action = "(inference)";
        }

        entry.formatted_facts.reserve(tr.new_fact_indices.size());
        for (const auto idx : tr.new_fact_indices) {
            if (idx >= facts.size())
                continue;
            const auto& fact = facts[idx];
            const auto pred_it = predicates.id_to_specification.find(fact.atom.pred);
            if (pred_it != predicates.id_to_specification.end())
                entry.formatted_facts.push_back(FormatFactMessage(fact, pred_it->second));
            else
                entry.formatted_facts.push_back(fact.details);
        }
        result.push_back(std::move(entry));
    }
    return result;
}

} // namespace GView::Components::AnalysisEngine
