#include "AnalysisEngineInternal.hpp"

#include <AppCUI/include/AppCUI.hpp>
#include <algorithm>

namespace GView::Components::AnalysisEngine
{
namespace
{
    constexpr std::string_view SECTION_NAME_ANALYSIS_ENGINE = "AnalysisEngine";
    constexpr std::string_view KEY_CLOSURE_MODE             = "ClosureMode";
    constexpr std::string_view KEY_MAX_CLOSURE_ITERATIONS     = "MaxClosureIterations";
    constexpr std::string_view KEY_CONTRADICTIONS             = "Contradictions";

    [[nodiscard]] ClosureMode ParseClosureMode(std::string_view value) noexcept
    {
        if (value == "manual")
            return ClosureMode::Manual;
        return ClosureMode::Auto;
    }

    [[nodiscard]] std::vector<ContradictionPairNames> ParseContradictionNames(std::string_view value)
    {
        std::vector<ContradictionPairNames> pairs;
        if (value.empty())
            return pairs;

        std::string_view remaining = value;
        while (!remaining.empty()) {
            const auto sep    = remaining.find(';');
            const auto token  = (sep == std::string_view::npos) ? remaining : remaining.substr(0, sep);
            const auto colon  = token.find(':');
            if (colon != std::string_view::npos) {
                ContradictionPairNames pair;
                pair.predicate_a = std::string(token.substr(0, colon));
                pair.predicate_b = std::string(token.substr(colon + 1));
                if (!pair.predicate_a.empty() && !pair.predicate_b.empty())
                    pairs.push_back(std::move(pair));
            }
            if (sep == std::string_view::npos)
                break;
            remaining.remove_prefix(sep + 1);
        }
        return pairs;
    }
} // namespace

void AnalysisEngineConfig::Update(AppCUI::Utils::IniSection sect)
{
    sect.UpdateValue(KEY_CLOSURE_MODE, "auto", true);
    sect.UpdateValue(KEY_MAX_CLOSURE_ITERATIONS, "256", true);
    sect.UpdateValue(KEY_CONTRADICTIONS, "", true);
}

void AnalysisEngineConfig::Initialize(AnalysisEngineConfig& cfg)
{
    cfg.closure_mode           = ClosureMode::Auto;
    cfg.max_closure_iterations = 256;
    cfg.contradictions.clear();
    cfg.contradiction_names.clear();

    const auto ini = AppCUI::Application::GetAppSettings();
    if (!ini)
        return;

    auto sect = ini->GetSection(SECTION_NAME_ANALYSIS_ENGINE);
    if (!sect.Exists())
        return;

    cfg.closure_mode        = ParseClosureMode(sect.GetValue(KEY_CLOSURE_MODE).ToString());
    const auto max_iter     = sect.GetValue(KEY_MAX_CLOSURE_ITERATIONS).ToUInt32(256);
    cfg.max_closure_iterations = max_iter < 1 ? 1u : max_iter;
    cfg.contradiction_names = ParseContradictionNames(sect.GetValue(KEY_CONTRADICTIONS).ToString());
}

} // namespace GView::Components::AnalysisEngine
