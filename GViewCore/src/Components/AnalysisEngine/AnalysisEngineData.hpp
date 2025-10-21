#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

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
    std::string explanation; // TODO: consider class ?
};
void to_json(nlohmann::json& j, const PredicateSpecification& p);
void from_json(const nlohmann::json& j, PredicateSpecification& p);
bool VerifyPredicates(const std::vector<PredicateSpecification>& predicates);

}