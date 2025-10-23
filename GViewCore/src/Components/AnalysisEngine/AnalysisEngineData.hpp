#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <AppCUI/include/AppCUI.hpp>
#include "GView.hpp"

struct TransparentHash {
    using is_transparent = void;  // Enables heterogeneous lookup
    using key_equal = std::equal_to<>;

    size_t operator()(std::string_view sv) const noexcept {
        return std::hash<std::string_view>{}(sv);
    }
};

struct TransparentEqual {
    using is_transparent = void;
    bool operator()(std::string_view a, std::string_view b) const noexcept {
        return a == b;
    }
};

template <typename T>
using StringKeyMap = std::unordered_map<std::string, T, TransparentHash, TransparentEqual>;

namespace GView::Components::AnalysisEngine
{

struct Status {
    bool ok{ true };
    std::string message;
    static Status OK()
    {
        return Status{};
    }
    static Status Error(std::string msg)
    {
        Status s;
        s.ok      = false;
        s.message = std::move(msg);
        return s;
    }
};

struct PredicateSpecification {
    std::string name;
    std::vector<std::string> arguments;
    std::string explanation;
};
void to_json(nlohmann::json& j, const PredicateSpecification& p);
void from_json(const nlohmann::json& j, PredicateSpecification& p);
bool VerifyPredicates(const std::vector<PredicateSpecification>& predicates, void*);

struct RuleSpecification {
    std::string name;
    std::vector<std::string> body;      // list of predicate names
    std::vector<std::string> head;      // list of predicates or action names
    std::unordered_map<std::string, std::string> variable_mapping; // [optional] argument remapping
    std::string explanation;
    Confidence confidence = 0; // 0-100
};
void to_json(nlohmann::json& j, const RuleSpecification& p);
void from_json(const nlohmann::json& j, RuleSpecification& p);
bool VerifyPredicates(const std::vector<RuleSpecification>& rules, void* extra_ctx);

inline TimePoint now() noexcept
{
    return Clock::now();
}

// A literal (possibly negated) that must hold
struct PredLiteral {
    PredId pred;
    bool negated{ false };
};

// One conjunctive clause over a subject, with optional time window requirement
struct ConjClause {
    std::vector<PredLiteral> all_of; // AND over literals
    std::chrono::milliseconds window{ std::chrono::milliseconds{ 0 } };
};

// A rule: disjunction of conjunctive clauses (DNF). If any clause holds, emit suggestion.
struct Rule {
    RuleId id{ 0 };
    std::string name;
    ConjClause body; // keep single-clause for simplicity; duplicate Rule for ORs
    std::vector<PredOrAction> head; 
    Confidence confidence;
    std::unordered_map<std::string, std::string> variable_mapping;
    std::string explanation;
    std::chrono::milliseconds cooldown{ std::chrono::minutes(30) };
};

template<typename IdType, typename DataType>
struct SpecificationStorage
{
    IdType next_available_id{ 1 };
    StringKeyMap<IdType> name_to_id;
    std::unordered_map<IdType, DataType> id_to_specification;

    bool ExtractPredicates(const nlohmann::json& j, std::string_view field_name, void* extra_ctx = nullptr);
};

template <typename IdType, typename DataType>
bool SpecificationStorage<IdType, DataType>::ExtractPredicates(const nlohmann::json& j, std::string_view field_name, void* extra_ctx)
{
    auto field_it = j.find(field_name);
    if (field_it == j.end() || !field_it->is_array())
        return false;
    std::vector<DataType> entries = field_it->get<std::vector<DataType>>();
    if (!VerifyPredicates(entries, extra_ctx))
        return false;
    for (auto& p : entries) {
        IdType pred_id               = next_available_id++;
        name_to_id[p.name]           = pred_id;
        id_to_specification[pred_id] = std::move(p);
    }
    return true;
}
std::string variant_to_string(const Value& v);
std::string FillRuleTemplate(const Rule& r, std::vector<Reference<const Fact>>& matched_facts);

}