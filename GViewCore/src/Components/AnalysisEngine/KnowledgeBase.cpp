#include "KnowledgeBase.hpp"

#include <format>

namespace GView::Components::AnalysisEngine
{
namespace
{
    [[nodiscard]] uint64 HashValue(const Value& v) noexcept
    {
        return std::visit(
              [](auto&& arg) -> uint64 {
                  using T = std::decay_t<decltype(arg)>;
                  if constexpr (std::is_same_v<T, std::monostate>)
                      return 0;
                  else if constexpr (std::is_same_v<T, std::string>)
                      return std::hash<std::string>{}(arg);
                  else
                      return std::hash<T>{}(arg);
              },
              v);
    }
} // namespace

uint64 HashFactArgs(std::span<const Arg> args) noexcept
{
    uint64 h = 0xcbf29ce484222325ULL;
    for (const auto& arg : args) {
        h ^= std::hash<std::string>{}(arg.name) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= HashValue(arg.value) + 0x85ebca6b + (h << 6) + (h >> 2);
    }
    return h;
}

FactKey MakeFactKey(const Fact& fact) noexcept
{
    return FactKey{ fact.atom.pred, fact.atom.subject, HashFactArgs(fact.atom.args) };
}

std::span<const StateTransition> DisclosureTrace::TraceSpan() const noexcept
{
    std::shared_lock lk(mu_);
    return transitions_;
}

void DisclosureTrace::Append(StateTransition transition)
{
    std::unique_lock lk(mu_);
    transitions_.push_back(std::move(transition));
}

size_t DisclosureTrace::Size() const noexcept
{
    std::shared_lock lk(mu_);
    return transitions_.size();
}

KnowledgeBase::KnowledgeBase()
{
    auto root       = std::make_shared<SnapshotNode>();
    root->generation = next_generation_++;
    root->fact_count = 0;
    current_snapshot_ = std::move(root);
}

bool KnowledgeBase::SubjectEq(const Subject& a, const Subject& b) noexcept
{
    return a.kind == b.kind && a.value == b.value;
}

Status KnowledgeBase::Add(const Fact& f) noexcept
{
    try {
        std::unique_lock lk(mu_);
        const uint32 index = static_cast<uint32>(facts_.size());
        facts_.push_back(f);
        by_pred_[f.atom.pred].push_back(index);
        by_subject_[f.atom.subject].push_back(index);

        const auto key = MakeFactKey(f);
        latest_by_key_[key] = index;

        if (collecting_transition_.load(std::memory_order_relaxed)) {
            std::lock_guard collector_lk(collector_mu_);
            collected_indices_.push_back(index);
        }

        return Status::OK();
    } catch (const std::exception& e) {
        return Status::Error(std::format("KnowledgeBase::Add: {}", e.what()));
    } catch (...) {
        return Status::Error("KnowledgeBase::Add: unknown");
    }
}

bool KnowledgeBase::Exists(PredId p, const Subject& s) const noexcept
{
    return LastTime(p, s).has_value();
}

std::optional<TimePoint> KnowledgeBase::LastTime(PredId p, const Subject& s) const noexcept
{
    try {
        std::shared_lock lk(mu_);
        auto it = by_pred_.find(p);
        if (it == by_pred_.end())
            return std::nullopt;
        for (auto rit = it->second.rbegin(); rit != it->second.rend(); ++rit) {
            const Fact& f = facts_.at(*rit);
            if (SubjectEq(f.atom.subject, s))
                return f.time;
        }
        return std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<Reference<const Fact>> KnowledgeBase::GetFact(PredId p, const Subject& s) const noexcept
{
    try {
        std::shared_lock lk(mu_);
        auto it = by_pred_.find(p);
        if (it == by_pred_.end())
            return std::nullopt;
        for (auto rit = it->second.rbegin(); rit != it->second.rend(); ++rit) {
            const Fact& f = facts_.at(*rit);
            if (SubjectEq(f.atom.subject, s))
                return { &f };
        }
        return std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

bool KnowledgeBase::HasFactKey(const FactKey& key) const noexcept
{
    std::shared_lock lk(mu_);
    return latest_by_key_.contains(key);
}

std::shared_ptr<const SnapshotNode> KnowledgeBase::CurrentSnapshot() const noexcept
{
    std::shared_lock lk(mu_);
    return current_snapshot_;
}

std::span<const Fact> KnowledgeBase::FactsSpan() const noexcept
{
    std::shared_lock lk(mu_);
    return facts_;
}

DisclosureTrace& KnowledgeBase::GetDisclosureTrace() noexcept
{
    return disclosure_trace_;
}

const DisclosureTrace& KnowledgeBase::GetDisclosureTrace() const noexcept
{
    return disclosure_trace_;
}

DerivationIndex& KnowledgeBase::GetDerivationIndex() noexcept
{
    return derivation_index_;
}

const DerivationIndex& KnowledgeBase::GetDerivationIndex() const noexcept
{
    return derivation_index_;
}

void KnowledgeBase::BeginTransitionCollection() noexcept
{
    {
        std::lock_guard lk(collector_mu_);
        collected_indices_.clear();
    }
    collecting_transition_.store(true, std::memory_order_release);
}

void KnowledgeBase::EndTransitionCollection() noexcept
{
    collecting_transition_.store(false, std::memory_order_release);
}

bool KnowledgeBase::IsCollectingTransition() const noexcept
{
    return collecting_transition_.load(std::memory_order_acquire);
}

std::vector<uint32> KnowledgeBase::StealCollectedIndices() noexcept
{
    std::lock_guard lk(collector_mu_);
    return std::move(collected_indices_);
}

std::shared_ptr<const SnapshotNode> KnowledgeBase::AdvanceSnapshot() noexcept
{
    std::unique_lock lk(mu_);
    auto node           = std::make_shared<SnapshotNode>();
    node->parent        = current_snapshot_;
    node->generation    = next_generation_++;
    node->fact_count    = static_cast<uint32>(facts_.size());
    current_snapshot_   = node;
    return current_snapshot_;
}

void KnowledgeBase::RecordTransition(
      std::shared_ptr<const SnapshotNode> from_snapshot,
      std::optional<GroundAction> action,
      std::vector<uint32> new_indices) noexcept
{
    auto to = AdvanceSnapshot();

    StateTransition tr;
    tr.from_state       = std::move(from_snapshot);
    tr.action_executed  = std::move(action);
    tr.new_fact_indices = std::move(new_indices);
    tr.to_state         = std::move(to);
    tr.timestamp        = now();
    disclosure_trace_.Append(std::move(tr));
}

} // namespace GView::Components::AnalysisEngine
