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
    std::string explanation; // TODO: consider class ?
};

struct PredicateSpecificationStorage
{
    uint32 next_available_id{ 1 };
    StringKeyMap<PredId> name_to_id;
    std::unordered_map<PredId, PredicateSpecification> id_to_specification;

    bool ExtractPredicates(const nlohmann::json& j, std::string_view field_name);
};

}