#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <vector>

#include "AnalysisEngineInternal.hpp"

namespace GView::Components::AnalysisEngine
{

class DisclosureTrace
{
  public:
    [[nodiscard]] std::span<const StateTransition> TraceSpan() const noexcept;
    void Append(StateTransition transition);
    [[nodiscard]] size_t Size() const noexcept;

  private:
    mutable std::shared_mutex mu_;
    std::vector<StateTransition> transitions_;
};

// Persistent append-only fact log with delta-encoded snapshot chain (Γ_i).
class KnowledgeBase
{
  public:
    KnowledgeBase();

    [[nodiscard]] Status Add(const Fact& fact) noexcept;
    [[nodiscard]] bool Exists(PredId p, const Subject& s) const noexcept;
    [[nodiscard]] std::optional<TimePoint> LastTime(PredId p, const Subject& s) const noexcept;
    [[nodiscard]] std::optional<Reference<const Fact>> GetFact(PredId p, const Subject& s) const noexcept;
    [[nodiscard]] bool HasFactKey(const FactKey& key) const noexcept;
    [[nodiscard]] std::shared_ptr<const SnapshotNode> CurrentSnapshot() const noexcept;
    [[nodiscard]] std::span<const Fact> FactsSpan() const noexcept;
    [[nodiscard]] DisclosureTrace& GetDisclosureTrace() noexcept;
    [[nodiscard]] const DisclosureTrace& GetDisclosureTrace() const noexcept;
    [[nodiscard]] DerivationIndex& GetDerivationIndex() noexcept;
    [[nodiscard]] const DerivationIndex& GetDerivationIndex() const noexcept;

    void BeginTransitionCollection() noexcept;
    void EndTransitionCollection() noexcept;
    [[nodiscard]] bool IsCollectingTransition() const noexcept;
    [[nodiscard]] std::vector<uint32> StealCollectedIndices() noexcept;

    [[nodiscard]] std::shared_ptr<const SnapshotNode> AdvanceSnapshot() noexcept;

    void RecordTransition(
          std::shared_ptr<const SnapshotNode> from_snapshot,
          std::optional<GroundAction> action,
          std::vector<uint32> new_indices) noexcept;

  private:
    struct SubjectHash {
        [[nodiscard]] size_t operator()(const Subject& s) const noexcept
        {
            if (s.kind == Subject::SubjectType::None)
                return 0u;
            return std::hash<uint64_t>{}(s.value) ^ 0x9e3779b97f4a7c15ULL;
        }
    };

    static bool SubjectEq(const Subject& a, const Subject& b) noexcept;

    mutable std::shared_mutex mu_;
    std::vector<Fact> facts_;
    std::unordered_map<PredId, std::vector<uint32>> by_pred_;
    std::unordered_map<Subject, std::vector<uint32>, SubjectHash> by_subject_;
    std::unordered_map<FactKey, uint32, FactKeyHash> latest_by_key_;

    std::shared_ptr<const SnapshotNode> current_snapshot_;
    uint32 next_generation_{ 0 };

    DisclosureTrace disclosure_trace_;
    DerivationIndex derivation_index_;

    std::atomic<bool> collecting_transition_{ false };
    std::vector<uint32> collected_indices_;
    std::mutex collector_mu_;
};

[[nodiscard]] uint64 HashFactArgs(std::span<const Arg> args) noexcept;
[[nodiscard]] FactKey MakeFactKey(const Fact& fact) noexcept;

} // namespace GView::Components::AnalysisEngine
