#include "AnalysisEngineData.hpp"

#include <regex>
#include <unordered_set>

using nlohmann::json;
using namespace AppCUI::Utils;
using namespace GView::Components::AnalysisEngine;

namespace
{

// Double braces {{...}} are treated as escaped and ignored.
std::unordered_set<std::string> extract_placeholders(const std::string& explanation)
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

bool verify_predicate(const PredicateSpecification& pred, std::vector<std::string>& errors)
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

bool verify_rule(const RuleSpecification& rule, std::vector<std::string>& errors, void* extra_ctx)
{
    if (!extra_ctx)
        return false;
    auto prev_data = (std::tuple<SpecificationStorage<PredId, PredicateSpecification>*, SpecificationStorage<ActId, PredicateSpecification>*>*) extra_ctx;
    auto predicate_storage_ptr = std::get<0>(*prev_data);
    auto action_storage_ptr    = std::get<1>(*prev_data);
    bool ok                    = true;

    std::unordered_set<std::string> args;
    for (const auto& clause : rule.clauses) {
        auto pred_it = predicate_storage_ptr->name_to_id.find(clause);
        if (pred_it != predicate_storage_ptr->name_to_id.end()) {
            auto& pred_specification = predicate_storage_ptr->id_to_specification[pred_it->second];
            args.insert(pred_specification.arguments.begin(), pred_specification.arguments.end());
            continue;
        }
        auto act_it = action_storage_ptr->name_to_id.find(clause);
        if (act_it != action_storage_ptr->name_to_id.end()) {
            auto& act_specification = action_storage_ptr->id_to_specification[act_it->second];
            args.insert(act_specification.arguments.begin(), act_specification.arguments.end());
            continue;
        }
        errors.emplace_back("[ERROR] Rule '" + rule.name + "' uses unknown predicate '" + clause + "' in clauses.");
        ok = false;
    }

    std::unordered_set<std::string> expected_args;
    for (const auto& result : rule.results) {
        auto pred_it = predicate_storage_ptr->name_to_id.find(result);
        if (pred_it != predicate_storage_ptr->name_to_id.end()) {
            auto& pred_specification = predicate_storage_ptr->id_to_specification[pred_it->second];
            expected_args.insert(pred_specification.arguments.begin(), pred_specification.arguments.end());
            continue;
        }
        auto act_it = action_storage_ptr->name_to_id.find(result);
        if (act_it != action_storage_ptr->name_to_id.end()) {
            auto& act_specification = action_storage_ptr->id_to_specification[act_it->second];
            expected_args.insert(act_specification.arguments.begin(), act_specification.arguments.end());
            continue;
        }
        errors.emplace_back("[ERROR] Rule '" + rule.name + "' uses unknown predicate '" + result + "' in results.");
        ok = false;
    }

    const auto placeholders = extract_placeholders(rule.explanation);
    expected_args.insert(placeholders.begin(), placeholders.end());

    for (const auto& mapping : rule.variable_mapping) {
        auto arg_it = args.find(mapping.first);
        if (arg_it == args.end()) {
            errors.emplace_back("[ERROR] Rule '" + rule.name + "' uses mapping '" + mapping.first + "' that is not among the clauses.");
            ok = false;
            continue;
        }
        args.insert(mapping.second);
    }

    LocalString<512> buffer;
    // Check if placeholders exist in arguments
    for (const auto& arg : expected_args) {
        if (!args.contains(arg)) {
            buffer.SetFormat("[ERROR] Rule '%s' uses placeholder {%s} not found in arguments.", rule.name.c_str(), arg.c_str());
            errors.emplace_back(buffer.GetText());
            ok = false;
        }
    }

    return ok;
}

} // namespace

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

bool VerifyPredicates(const std::vector<PredicateSpecification>& predicates, void*)
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

void to_json(json& j, const RuleSpecification& p)
{
    j = json{ { "name", p.name },
              { "clauses", p.clauses },
              { "results", p.results },
              { "explanation", p.explanation },
              { "variable_mapping", p.variable_mapping },
              { "confidence", p.confidence } };
}
void from_json(const json& j, RuleSpecification& p)
{
    try {
        j.at("name").get_to(p.name);
        j.at("clauses").get_to(p.clauses);
        j.at("results").get_to(p.results);
        j.at("explanation").get_to(p.explanation);
        j.at("confidence").get_to(p.confidence);
        auto mapping_it = j.find("variable_mapping");
        if (mapping_it != j.end() && mapping_it->is_object()) {
            mapping_it->get_to(p.variable_mapping);
        }
        if (p.confidence > 100) {
            LocalString<256> buffer;
            buffer.SetFormat("Invalid confidence value for RuleSpecification %s bigger than 100: %u", p.name.c_str(), (uint32) p.confidence);
            throw std::runtime_error(buffer.GetText());
        }

    } catch (const json::exception& e) {
        throw std::runtime_error("Invalid JSON structure for RuleSpecification: " + std::string(e.what()));
    }
}

bool VerifyPredicates(const std::vector<RuleSpecification>& rules, void* extra_ctx)
{
    if (!extra_ctx)
        return false;

    std::vector<std::string> errors;
    for (const auto& rule : rules) {
        if (!verify_rule(rule, errors, extra_ctx)) {
            errors.push_back("Rule '" + rule.name + "' verification failed.");
        }
    }

    if (!errors.empty()) {
        LocalString<4096> buffer;
        for (const auto& err : errors) {
            buffer.Add(err.c_str());
            buffer.Add("\n");
        }
        AppCUI::Dialogs::MessageBox::ShowError("Rule Verification Errors", buffer.GetText());
        return false;
    }

    return true;
}

} // namespace GView::Components::AnalysisEngine