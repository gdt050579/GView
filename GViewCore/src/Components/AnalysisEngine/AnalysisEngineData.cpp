#include "AnalysisEngineData.hpp"

#include <regex>
#include <unordered_set>
#include <AppCUI/include/AppCUI.hpp>

using nlohmann::json;
using namespace AppCUI::Utils;
using namespace GView::Components::AnalysisEngine;

// Double braces {{...}} are treated as escaped and ignored.
static std::unordered_set<std::string> extract_placeholders(const std::string& explanation)
{
    static const std::regex placeholder_regex(R"(\{([A-Za-z0-9_]+)\})");

    std::unordered_set<std::string> params;
    std::smatch match;
    std::string::const_iterator searchStart(explanation.cbegin());

    while (std::regex_search(searchStart, explanation.cend(), match, placeholder_regex)) {
        size_t pos = static_cast<size_t>(match.position(0));
        // --- Check for escaped {{
        bool escaped = (pos > 0 && explanation[pos - 1] == '{');
        if (!escaped) {
            params.insert(match[1].str());
        }
        searchStart = match.suffix().first;
    }
    return params;
}

static bool verify_predicate(const PredicateSpecification& pred, std::vector<std::string>& errors)
{
    const auto placeholders = extract_placeholders(pred.explanation);
    std::unordered_set<std::string> args(pred.arguments.begin(), pred.arguments.end());
    bool ok = args.size() == pred.arguments.size();

    if (!ok) {
        errors.emplace_back("[ERROR] Predicate '%s' has duplicated arguments.");
    }

    LocalString<512> buffer;

    // Check if placeholders exist in arguments
    for (const auto& p : placeholders) {
        if (!args.contains(p)) {
            buffer.SetFormat("[ERROR] Predicate '%s' uses placeholder {%s} not found in arguments.", pred.name.c_str(), p.c_str());
            errors.emplace_back(buffer.GetText());
            ok = false;
        }
    }

    // Check if arguments are unused
    for (const auto& arg : args) {
        if (!placeholders.contains(arg)) {
            buffer.SetFormat("[WARNING] Predicate '%s' argument {%s} not used in explanation.", pred.name.c_str(), arg);
            errors.emplace_back(buffer.GetText());
        }
    }

    return ok;
}

namespace GView::Components::AnalysisEngine
{

void to_json(json& j, const PredicateSpecification& p)
{
    j = json{ { "name", p.name }, { "arguments", p.arguments }, { "explanation", p.explanation } };
}
void from_json(const json& j, PredicateSpecification& p)
{
    try {
        j.at("name").get_to(p.name);
        j.at("arguments").get_to(p.arguments);
        j.at("explanation").get_to(p.explanation);
    } catch (const json::exception& e) {
        throw std::runtime_error("Invalid JSON structure for PredicateSpecification: " + std::string(e.what()));
    }
}

bool VerifyPredicates(const std::vector<PredicateSpecification>& predicates)
{
    std::vector<std::string> errors;
    for (const auto& pred : predicates) {
        if (!verify_predicate(pred, errors)) {
            errors.push_back("Predicate '" + pred.name + "' verification failed.");
        }
    }

    if (!errors.empty()) {
        LocalString<4096> buffer;
        for (const auto& err : errors) {
            buffer.Add(err.c_str());
            buffer.Add("\n");
        }
        AppCUI::Dialogs::MessageBox::ShowError("Predicate Verification Errors", buffer.GetText());
        return false;
    }

    return true;
}

} // namespace GView::Components::AnalysisEngine