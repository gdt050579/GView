#pragma once
#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "AnalysisEngineData.hpp"
#include "GView.hpp"

constexpr bool DISPLAY_FACTS_AS_ANALYSIS_NOTES = true;

namespace GView::Components::AnalysisEngine
{

struct SubjectParentInfo {
    uint64 direct_parent;
    uint64 main_parent;
};

class AnalysisEngineWindow;
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
    std::vector<bool> RegisterActionTrigger(const std::vector<ActId>& action_ids, Reference<RuleTriggerInterface> trigger) override;
    Subject GetSubjectForNewWindow(Object::Type objectType) override;
    void RegisterSubjectWithParent(const Subject& currentWindow, Reference<Subject> parentWindow) override;
    void AddAnalysisNotes(const Subject& currentWindow, std::string data) override;

    uint64 FindMainParent(uint64 current_subject);

    std::vector<Suggestion> evaluate(const Subject& s) noexcept;

    Status set_fact(const Fact& f) noexcept;
    Status set_fact(PredId p, const Subject& s, std::string source) noexcept;
    
    std::string GetRulePredicates(RuleId rule_id) const;

    const std::vector<Suggestion>& GetAllAvailableSuggestions() const
    {
        return current_suggestions;
    }

    // Small helpers
    bool TryExecuteSuggestionByArrayIndex(uint32 index, bool& shouldCloseAnalysisWindow);
    bool TryExecuteSuggestionBySuggestionId(SuggestionId id, bool& shouldCloseAnalysisWindow);
    Reference<const Suggestion> GetSuggestionById(SuggestionId id) const;
  private:
    Status register_rule(const Rule& r) noexcept;

    static PredLiteral lit(PredId p, bool neg = false) noexcept
    {
        return PredLiteral{ p, neg };
    }
    static ConjClause clause(std::initializer_list<PredLiteral> all, std::chrono::milliseconds window = std::chrono::milliseconds{ 0 })
    {
        ConjClause c;
        c.all_of.assign(all.begin(), all.end());
        c.window = window;
        return c;
    }
    static ConjClause clause(std::vector<PredLiteral> all, std::chrono::milliseconds window = std::chrono::milliseconds{ 0 })
    {
        ConjClause c;
        c.all_of = std::move(all);
        c.window = window;
        return c;
    }


    struct Impl;
    Reference<AnalysisEngineWindow> engineWindow;
    std::unique_ptr<Impl> impl_;
    std::vector<Suggestion> current_suggestions;
    SuggestionId next_suggestion_id = { 1 };

    std::unordered_map<ActId, std::vector<Reference<RuleTriggerInterface>>> action_handlers;
    std::atomic<uint32> next_available_subject{ 1 };

    SpecificationStorage<PredId, PredicateSpecification> predicates;
    SpecificationStorage<ActId, PredicateSpecification> actions;
    SpecificationStorage<RuleId, Rule> rules;
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
