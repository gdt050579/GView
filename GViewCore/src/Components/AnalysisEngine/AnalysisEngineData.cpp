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

std::string variant_to_string(const Value& v)
{
    return std::visit(
          [](const auto& arg) -> std::string {
              using T = std::decay_t<decltype(arg)>;
              if constexpr (std::is_same_v<T, std::monostate>) {
                  return "(null)";
              } else if constexpr (std::is_same_v<T, bool>) {
                  return arg ? "true" : "false";
              } else if constexpr (std::is_same_v<T, int64_t>) {
                  return std::to_string(arg);
              } else if constexpr (std::is_same_v<T, uint64_t>) {
                  return std::to_string(arg);
              } else if constexpr (std::is_same_v<T, double>) {
                  std::ostringstream oss;
                  oss << std::fixed << std::setprecision(4) << arg;
                  return oss.str();
              } else if constexpr (std::is_same_v<T, std::string>) {
                  return "\"" + arg + "\"";
              } else {
                  // Should not happen if all types are covered
                  return "Unknown Type Error";
              }
          },
          v);
}

std::string format_message(
      const std::string& message_template, const StringKeyMap<std::string>& arguments, const std::unordered_set<std::string>& valid_placeholders)
{
    std::string result;
    result.reserve((size_t) ((double) message_template.length() * 1.2));

    size_t current_pos = 0;

    while (current_pos < message_template.length()) {
        size_t start_pos = message_template.find('{', current_pos);
        result.append(message_template, current_pos, start_pos - current_pos);
        if (start_pos == std::string::npos) {
            break;
        }
        if (start_pos + 1 < message_template.length() && message_template[start_pos + 1] == '{') {
            // Found '{{', treat as a literal '{'
            result.append("{");
            current_pos = start_pos + 2; 
            continue;                    
        }
        size_t end_pos = message_template.find('}', start_pos + 1);
        if (end_pos == std::string::npos) {
            LocalString<128> buffer;
            buffer.SetFormat("Malformed template: Placeholder opened at index %z is not closed.", start_pos);
            throw std::runtime_error(buffer.GetText());
        }

        size_t key_start = start_pos + 1;
        size_t key_len   = end_pos - key_start;
        // TODO: consider string_view to avoid allocations.
        std::string key = message_template.substr(key_start, key_len);
        current_pos = end_pos + 1; // after '}'
        if (key.empty()) {             // empty placeholder {} TODO: decide how to handle
            result.append("{}", 2);
            continue;
        }

        if (!valid_placeholders.contains(key)) {
            result.append("{" + key + "}");// Treat unknown keys as a literal string to prevent injection.
            continue;
        }

        auto it = arguments.find(key);
        if (it != arguments.end()) {
            result.append(it->second);
        } else {
            result.append("<MISSING_ARG:" + key + ">");
        }
    }

    return result;
}

std::string FillRuleTemplate(const Rule& r, std::vector<Reference<const Fact>>& matched_facts)
{
    const auto placeholders = extract_placeholders(r.explanation);
    StringKeyMap<std::string> argument_with_values;

    for (auto& fact : matched_facts) {
        for (const auto& arg : fact->atom.args) {
            argument_with_values[arg.name] = variant_to_string(arg.value);
        }
    }
    for (const auto& mapping : r.variable_mapping) {
        auto arg_it = argument_with_values.find(mapping.first);
        if (arg_it == argument_with_values.end()) {
            // error: mapping from unknown argument
            assert(false); // report this !!
            continue;
        }
        argument_with_values[mapping.second] = arg_it->second;
    }

    try {
        auto result = format_message(r.explanation, argument_with_values, placeholders);
        return result;
    } catch (std::exception& e) {
        return "[ERROR] Failed to format rule explanation: " + std::string(e.what());
    }
}

} // namespace GView::Components::AnalysisEngine