#include "SummaryAssistant.hpp"
#include "Explanation.hpp"

#include <charconv>

namespace GView::HDF
{
std::string SummaryAssistant::SerializeKnowledgeState(const DisclosureSession& session, std::span<const GroundActionId> selectable)
{
    std::string prompt = "You assist a malware analyst who explores an artifact with the Hybrid Disclosure Framework.\n";
    prompt += "Knowledge state (Gamma, " + std::to_string(session.Gamma().Size()) + " ground assertions):\n";
    const auto& gamma  = session.Gamma();
    const uint32 count = std::min(gamma.Size(), MAX_ASSERTIONS_IN_PROMPT);
    for (AssertionId a = 0; a < count; a++) {
        if (gamma.Predicate(a) == session.GetSignature().hasName)
            continue;
        prompt += "- " + Denotation::Assertion(session, a) + "\n";
    }
    if (count < gamma.Size())
        prompt += "- ... (" + std::to_string(gamma.Size() - count) + " more)\n";
    prompt += "\nSelectable actions (the only actions that can be executed now):\n";
    for (size_t i = 0; i < selectable.size(); i++)
        prompt += std::to_string(i + 1) + ". " + Denotation::Action(session, selectable[i]) + "  [" + Denotation::ActionAtom(session, selectable[i]) + "]\n";
    prompt += "\nGive a brief analysis summary, then recommend the most useful actions, one per line, as 'ACTION: <number>' using the numbers "
              "above. Do not invent actions.\n";
    return prompt;
}

std::vector<GroundActionId> SummaryAssistant::ParseRecommendations(std::string_view response, std::span<const GroundActionId> selectable)
{
    std::vector<GroundActionId> result;
    constexpr std::string_view prefix = "ACTION:";
    while (!response.empty()) {
        const auto end = response.find('\n');
        auto line      = response.substr(0, end);
        response       = end == std::string_view::npos ? std::string_view() : response.substr(end + 1);
        while (!line.empty() && (line.front() == ' ' || line.front() == '*' || line.front() == '-'))
            line.remove_prefix(1);
        if (!line.starts_with(prefix))
            continue;
        line.remove_prefix(prefix.size());
        while (!line.empty() && line.front() == ' ')
            line.remove_prefix(1);
        uint32 number   = 0;
        const auto conv = std::from_chars(line.data(), line.data() + line.size(), number);
        if (conv.ec != std::errc() || number == 0 || number > selectable.size())
            continue;
        const auto beta = selectable[number - 1];
        if (std::find(result.begin(), result.end(), beta) == result.end())
            result.push_back(beta);
    }
    return result;
}

SummaryResult SummaryAssistant::Request(
      const DisclosureSession& session,
      std::span<const GroundActionId> selectable,
      GView::CommonInterfaces::SmartAssistants::SmartAssistantPromptInterface* assistant)
{
    SummaryResult result;
    if (!assistant || GView::Security::RestrictedMode::IsFeatureDisabled(GView::Security::RestrictedMode::Feature::LLMHints))
        return result;
    const auto prompt  = SerializeKnowledgeState(session, selectable);
    bool success       = false;
    result.narrative   = assistant->AskSmartAssistant(prompt, "HDF analysis summary", success);
    result.success     = success;
    result.recommended = ParseRecommendations(result.narrative, selectable);
    return result;
}

} // namespace GView::HDF
