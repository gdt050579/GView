#include "SummaryController.hpp"

#include <sstream>

namespace GView::Components::AnalysisEngine
{
std::string SummaryController::SerializeKnowledgeState(
      std::span<const Fact> facts,
      const SpecificationStorage<PredId, PredicateSpecification>& predicates,
      const std::vector<Suggestion>& suggestions,
      const RuleEngine& engine) noexcept
{
    std::ostringstream oss;
    oss << "Knowledge state (Gamma):\n";
    for (const auto& fact : facts) {
        const auto pred_it = predicates.id_to_specification.find(fact.atom.pred);
        if (pred_it != predicates.id_to_specification.end())
            oss << "- " << FormatFactMessage(fact, pred_it->second) << '\n';
    }
    oss << "\nAvailable actions:\n";
    for (const auto& sug : suggestions) {
        for (const auto& res : sug.results) {
            if (res.type == PredOrAction::PredOrActionType::Action)
                oss << "- " << engine.GetActName(res.data.action_id) << ": " << sug.message << '\n';
        }
    }
    oss << "\nProvide a brief analysis summary and list recommended actions prefixed with 'ACTION:'.\n";
    return oss.str();
}

SummaryResult SummaryController::ParseAssistantResponse(std::string_view response) noexcept
{
    SummaryResult result;
    result.success   = !response.empty();
    result.narrative = std::string(response);

    std::string_view remaining = response;
    while (!remaining.empty()) {
        const auto line_end = remaining.find('\n');
        const auto line     = (line_end == std::string_view::npos) ? remaining : remaining.substr(0, line_end);
        constexpr std::string_view prefix = "ACTION:";
        if (line.size() > prefix.size() && line.substr(0, prefix.size()) == prefix) {
            auto action_name = line.substr(prefix.size());
            while (!action_name.empty() && action_name.front() == ' ')
                action_name.remove_prefix(1);
            if (!action_name.empty())
                result.recommended_actions.emplace_back(action_name);
        }
        if (line_end == std::string_view::npos)
            break;
        remaining.remove_prefix(line_end + 1);
    }
    return result;
}

SummaryResult SummaryController::RequestSummary(
      RuleEngine& engine,
      GView::CommonInterfaces::SmartAssistants::SmartAssistantPromptInterface* assistant) noexcept
{
    SummaryResult empty;
    if (assistant == nullptr)
        return empty;

    if (GView::Security::RestrictedMode::IsActive()) {
        const auto* policy = GView::Security::RestrictedMode::GetCurrentPolicy();
        if (policy != nullptr) {
            for (const auto feature : policy->disabledFeatures) {
                if (feature == GView::Security::RestrictedMode::Feature::LLMHints)
                    return empty;
            }
        }
    }

    const auto prompt = SerializeKnowledgeState(
          engine.GetFactsSpan(), engine.GetPredicateStorage(), engine.GetAllAvailableSuggestions(), engine);

    bool success = false;
    const auto response = assistant->AskSmartAssistant(prompt, "HDF Analysis Summary", success);
    auto parsed         = ParseAssistantResponse(response);
    parsed.success      = success;
    return parsed;
}

} // namespace GView::Components::AnalysisEngine
