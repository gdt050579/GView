#pragma once
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "GView.hpp"

namespace GView::Components::AnalysisEngine
{

// ----------------------------- Status ------------------------------------- //
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

template <typename T>
class StatusOr
{
  public:
    StatusOr() : s_(Status::Error("Uninitialized"))
    {
    }
    StatusOr(const Status& s) : s_(s)
    {
    }
    StatusOr(T v) : s_(Status::OK()), v_(std::move(v))
    {
    }
    bool ok() const noexcept
    {
        return s_.ok;
    }
    const Status& status() const noexcept
    {
        return s_;
    }
    const T& value() const
    {
        if (!s_.ok)
            throw std::runtime_error("StatusOr access error: " + s_.message);
        return *v_;
    }
    T& value()
    {
        if (!s_.ok)
            throw std::runtime_error("StatusOr access error: " + s_.message);
        return *v_;
    }
    const T* operator->() const
    {
        return &value();
    }
    T* operator->()
    {
        return &value();
    }

  private:
    Status s_;
    std::optional<T> v_;
};

inline TimePoint now() noexcept
{
    return Clock::now();
}

// Simple severity for suggestion UI
//enum class Severity : std::uint8_t { Info = 0, Warn = 1, High = 2, Critical = 3 };

// Action to propose (Suggest(Action))
//struct Action {
//    ActId key{};
//    Subject subject{};
//    std::vector<Arg> args;
//};
//struct Suggestion {
//    Action action;
//    Severity severity{ Severity::Info };
//    std::string message;                                            // human readable
//    std::chrono::milliseconds cooldown{ std::chrono::minutes(30) }; // suppression interval
//    TimePoint last_emitted{};                                       // zero == never
//};

// A literal (possibly negated) that must hold
struct Literal {
    PredId pred;
    bool negated{ false };
};

// One conjunctive clause over a subject, with optional time window requirement
struct ConjClause {
    std::vector<Literal> all_of; // AND over literals
    std::chrono::milliseconds window{ std::chrono::milliseconds{ 0 } };
};

// A rule: disjunction of conjunctive clauses (DNF). If any clause holds, emit suggestion.
struct Rule {
    std::string id;    // stable id for telemetry
    ConjClause clause; // keep single-clause for simplicity; duplicate Rule for ORs
    Action action;
    Confidence confidence = 0;
    std::string message;
    std::chrono::milliseconds cooldown{ std::chrono::minutes(30) };
};

enum class PredDefaultValues : PredId;

// ----------------------- Concrete RuleEngine Impl -------------------------- //
// RuleEngine: simple rule-based engine with built-in rules.
class RuleEngine final : public AnalysisEngineInterface
{
  public:
    RuleEngine();
    ~RuleEngine() noexcept override;

    bool Init() override;
    bool SubmitFact(const Fact& fact) override;
    ActId GetActId(std::string_view name) const override;
    PredId GetPredId(std::string_view name) const override;
    std::string_view GetPredName(PredId p) const;
    std::string_view GetActName(ActId a) const;
    void ShowAnalysisEngineWindow() override;
    bool RegisterActionTrigger(ActId action, Reference<RuleTriggerInterface> trigger) override;

    Status set_fact(const Fact& f) noexcept;
    Status set_fact(PredId p, const Subject& s, std::string source) noexcept;
    std::vector<Suggestion> evaluate(const Subject& s) noexcept;
    Status register_rule(const Rule& r) noexcept;
    Status install_builtin_rules() noexcept;

    const std::vector<Suggestion>& GetAllAvailableSuggestions() const
    {
        return current_suggestions;
    }


    // Small helpers
    static Literal lit(PredDefaultValues p, bool neg = false) noexcept
    {
        return Literal{ (PredId)p, neg };
    }
    static ConjClause clause(std::initializer_list<Literal> all, std::chrono::milliseconds window = std::chrono::milliseconds{ 0 })
    {
        ConjClause c;
        c.all_of.assign(all.begin(), all.end());
        c.window = window;
        return c;
    }
    bool TryExecuteSuggestion(uint32 index);
  private:

    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::vector<Suggestion> current_suggestions;
    std::unordered_map<ActId, std::vector<Reference<RuleTriggerInterface>>> action_handlers;
};

// Convenience helpers
inline Subject FileSubject(FileId id)
{
    return { Subject::SubjectType::File, id };
}
inline Subject UserSubject(UserId id)
{
    return { Subject::SubjectType::User, id };
}
inline Fact MakeFact(PredId p, const Subject& s, std::string source)
{
    Fact f;
    f.atom.pred    = p;
    f.atom.subject = s;
    f.source       = std::move(source);
    f.time         = now();
    return f;
}

} // namespace GView::Components::AnalysisEngine
