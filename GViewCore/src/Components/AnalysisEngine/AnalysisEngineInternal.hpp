#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "AnalysisEngineData.hpp"
#include "GView.hpp"

namespace GView::Components::AnalysisEngine
{

enum class Sort : uint8 {
    Subject = 0,
    String  = 1,
    Int     = 2,
    Real    = 3,
    Bool    = 4,
    URL     = 5,
};

struct FactKey {
    PredId pred{ INVALID_PRED_ID };
    Subject subject{};
    uint64 args_hash{ 0 };

    [[nodiscard]] bool operator==(const FactKey& other) const noexcept = default;
};

struct FactKeyHash {
    [[nodiscard]] size_t operator()(const FactKey& key) const noexcept
    {
        size_t h = std::hash<uint64_t>{}(key.pred);
        h ^= std::hash<uint64_t>{}(key.subject.value) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(static_cast<uint8_t>(key.subject.kind)) + 0x85ebca6b;
        h ^= key.args_hash + 0xc2b2ae35;
        return h;
    }
};

[[nodiscard]] uint64 HashFactArgs(std::span<const Arg> args) noexcept;
[[nodiscard]] FactKey MakeFactKey(const Fact& fact) noexcept;

// Theory Note: Snapshots are prefix markers over an append-only log, not Okasaki-style
// persistent structures; rollback is intentionally unsupported (HDF disclosure is monotone).
struct SnapshotNode final {
    std::shared_ptr<const SnapshotNode> parent;
    uint32 generation{ 0 };
    uint32 fact_count{ 0 };

    [[nodiscard]] uint32 DeltaCount() const noexcept
    {
        const uint32 parent_count = parent ? parent->fact_count : 0;
        return fact_count - parent_count;
    }
};

struct GroundAction {
    ActId action_id{ INVALID_ACT_ID };
    std::vector<Arg> args;
};

struct StateTransition {
    std::shared_ptr<const SnapshotNode> from_state;
    std::optional<GroundAction> action_executed;
    std::vector<uint32> new_fact_indices;
    std::shared_ptr<const SnapshotNode> to_state;
    TimePoint timestamp{};
};

enum class DerivationSourceType : uint8 {
    Rule              = 0,
    Action            = 1,
    InitialExtraction = 2,
};

struct DerivationNode {
    FactKey derived_key;
    DerivationSourceType source_type{ DerivationSourceType::InitialExtraction };
    RuleId source_rule_id{ INVALID_RULE_ID };
    ActId source_action_id{ INVALID_ACT_ID };
    std::vector<std::shared_ptr<const DerivationNode>> dependencies;
};

using DerivationIndex = std::unordered_map<FactKey, std::shared_ptr<const DerivationNode>, FactKeyHash>;

enum class ClosureMode : uint8 {
    Auto   = 0,
    Manual = 1,
};

struct ContradictionPair {
    PredId predicate_a{ INVALID_PRED_ID };
    PredId predicate_b{ INVALID_PRED_ID };
};

struct ContradictionPairNames {
    std::string predicate_a;
    std::string predicate_b;
};

struct AnalysisEngineConfig {
    ClosureMode closure_mode{ ClosureMode::Auto };
    uint32 max_closure_iterations{ 256 };
    std::vector<ContradictionPair> contradictions;
    std::vector<ContradictionPairNames> contradiction_names;

    static void Update(AppCUI::Utils::IniSection sect);
    static void Initialize(AnalysisEngineConfig& cfg);
};

} // namespace GView::Components::AnalysisEngine
