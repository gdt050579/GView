#pragma once

// The LLM selection assistant of the HDF window (Summary tab). It only ever sees Gamma_i (rendered with den) and the
// numbered Selectable(Gamma_i); it recommends ground actions by number ("ACTION: <n>") and never executes anything and
// never extends the vocabulary or the rules (the analyst confirms every step).

#include "DisclosureSession.hpp"

namespace GView::HDF
{
struct SummaryResult {
    std::string narrative;
    std::vector<GroundActionId> recommended; // a subset of the selectable actions, in the order given by the assistant
    bool success{ false };
};

class SummaryAssistant
{
  public:
    static constexpr uint32 MAX_ASSERTIONS_IN_PROMPT = 2000;

    static std::string SerializeKnowledgeState(const DisclosureSession& session, std::span<const GroundActionId> selectable);
    // "ACTION: <n>" lines; n is 1-based in the numbered list; unknown / duplicate numbers are ignored
    static std::vector<GroundActionId> ParseRecommendations(std::string_view response, std::span<const GroundActionId> selectable);
    // nullptr assistant or LLM hints disabled by the course policy -> success = false
    static SummaryResult Request(
          const DisclosureSession& session,
          std::span<const GroundActionId> selectable,
          GView::CommonInterfaces::SmartAssistants::SmartAssistantPromptInterface* assistant);
};

} // namespace GView::HDF
