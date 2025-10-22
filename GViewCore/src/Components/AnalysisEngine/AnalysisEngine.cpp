#include "AnalysisEngine.hpp"
#include "AnalysisEngineWindow.hpp"

#include <cassert>
#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <regex>
using nlohmann::json;

namespace GView::Components::AnalysisEngine
{
PredicateStorage AnalysisEngineInterface::RequestPredicateStorage(const std::vector<std::string_view>& predicates) const
{
    PredicateStorage storage;
    for (const auto& p : predicates) {
        auto res = GetPredId(p);
        if (IsValidPredicateId(res)) {
            PredicateEntry entry = { std::string(p), res };
            storage.predicates.emplace_back(std::move(entry));
        } else {
            storage.failed_predicates.emplace_back(std::string(p));
        }
    }
    return storage;
}

bool AnalysisEngineInterface::RequestPredicate(PredicateStorage& predicateStorage, std::string_view predicate) const
{
    for (const auto& p : predicateStorage.predicates)
        if (p.name == predicate)
            return true;
    auto res = GetPredId(predicate);
    if (IsValidPredicateId(res)) {
        PredicateEntry entry = { std::string(predicate), res };
        predicateStorage.predicates.emplace_back(std::move(entry));
        return true;
    }
    predicateStorage.failed_predicates.emplace_back(std::string(predicate));
    return false;
}

// Implementation from GView::Components::AnalysisEngine::AnalysisEngineInterface
Atom AnalysisEngineInterface::CreateAtomFromPredicateAndSubject(PredId pred, Reference<Subject> subject, std::vector<Arg> args)
{
    return Atom{ pred, subject, std::move(args) };
}

Fact AnalysisEngineInterface::CreateFactFromPredicateAndSubject(
      PredId pred, Reference<Subject> subject, std::string_view source, std::string_view details, std::vector<Arg> args)
{
    auto atom = CreateAtomFromPredicateAndSubject(pred, subject, std::move(args));
    return Fact{ .atom = atom, .time = now(), .source = std::string(source), .details = std::string(details) };
}

// ------------------------- Internal Structures ----------------------------- //
namespace
{

    struct SubjectHash {
        size_t operator()(const Subject& s) const noexcept
        {
            if (s.kind == Subject::SubjectType::None)
                return 0u;
            return std::hash<uint64_t>{}(s.value) ^ 0x9e3779b97f4a7c15ULL;
        }
    };

    class FactStore
    {
      public:
        Status add(const Fact& f) noexcept
        {
            try {
                std::unique_lock lk(mu_);
                facts_.emplace_back(f);
                by_pred_[f.atom.pred].push_back(facts_.size() - 1);
                by_subject_[f.atom.subject].push_back(facts_.size() - 1);
                return Status::OK();
            } catch (const std::exception& e) {
                const auto err = std::format("FactStore::add: {}", e.what());
                return Status::Error(err);
            } catch (...) {
                return Status::Error("FactStore::add: unknown");
            }
        }

        bool exists(PredId p, const Subject& s) const noexcept
        {
            return last_time(p, s).has_value();
        }

        // Retrieve latest fact timestamps for a given predicate+subject
        std::optional<TimePoint> last_time(PredId p, const Subject& s) const noexcept
        {
            try {
                std::shared_lock lk(mu_);
                auto it = by_pred_.find(p);
                if (it == by_pred_.end())
                    return std::nullopt;
                for (auto rit = it->second.rbegin(); rit != it->second.rend(); ++rit) {
                    const Fact& f = facts_.at(*rit);
                    if (subject_eq(f.atom.subject, s))
                        return f.time;
                }
                return std::nullopt;
            } catch (...) {
                return std::nullopt;
            }
        }

        std::optional<Reference<const Fact>> get_fact(PredId p, const Subject& s) const noexcept
        {
            try {
                std::shared_lock lk(mu_);
                auto it = by_pred_.find(p);
                if (it == by_pred_.end())
                    return std::nullopt;
                for (auto rit = it->second.rbegin(); rit != it->second.rend(); ++rit) {
                    const Fact& f = facts_[*rit];
                    if (subject_eq(f.atom.subject, s)) {
                        return { &f };
                    }
                }
                return std::nullopt;
            } catch (...) {
                return std::nullopt;
            }
        }

      private:
        static bool subject_eq(const Subject& a, const Subject& b) noexcept
        {
            if (a.kind != b.kind)
                return false;
            return a.value == b.value;
        }

        mutable std::shared_mutex mu_;
        std::vector<Fact> facts_;
        std::unordered_map<PredId, std::vector<size_t>> by_pred_;
        std::unordered_map<Subject, std::vector<size_t>, SubjectHash> by_subject_;
    };

    class SuggestionBus
    {
      public:
        // Returns true if suggestion should be emitted (not suppressed)
        bool should_emit(const std::vector<PredOrAction>& results, std::chrono::milliseconds cooldown, const Subject& s) noexcept
        {
            try {
                auto key = make_key(results, s);
                auto t   = now();
                std::unique_lock lk(mu_);
                auto it = last_.find(key);
                if (it == last_.end()) {
                    last_[key] = t;
                    return true;
                }
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t - it->second);
                if (elapsed >= cooldown) {
                    it->second = t;
                    return true;
                }
                return false;
            } catch (...) {
                return true;
            }
        }

      private:
        using Key = std::string; // derived from action key + subject
        static Key make_key(const std::vector<PredOrAction>& results, const Subject& s)
        {
            LocalString<256> buffer;
            for (const auto& res : results) {
                buffer.AddFormat("%ull#", res.data.action_id);
            }
            buffer.AddFormat("%u#%ull", (uint32) s.kind, s.value);
            return { buffer.GetText() };
        }
        std::mutex mu_;
        std::unordered_map<Key, TimePoint> last_;
    };

    struct RuleEngineState {
        FactStore facts;
        SuggestionBus bus;
        std::vector<Rule> rules;
        std::mutex mu_rules; // protects rules
    };

} // anonymous namespace

// ------------------------------ RuleEngine --------------------------------- //
struct RuleEngine::Impl {
    RuleEngineState st;

    bool holds(const ConjClause& c, const Subject& s, std::vector<Reference<const Fact>>& facts) const noexcept
    {
        facts.reserve(c.all_of.size());
        const auto t_now = now();
        for (const auto& L : c.all_of) {
            auto optional_fact = st.facts.get_fact(L.pred, s);
            const bool present = optional_fact.has_value();
            if (!L.negated) {
                if (!present)
                    return false;
                if (c.window.count() > 0) {
                    auto last = st.facts.last_time(L.pred, s);
                    if (!last.has_value())
                        return false;
                    auto age = std::chrono::duration_cast<std::chrono::milliseconds>(t_now - *last);
                    if (age > c.window)
                        return false;
                }
            } else {
                if (present)
                    return false;
            }
            if (present)
                facts.emplace_back(optional_fact.value());
        }
        return true;
    }
};

RuleEngine::RuleEngine() : engineWindow(nullptr), impl_(std::make_unique<Impl>())
{
    current_suggestions.reserve(8);
}
RuleEngine::~RuleEngine() noexcept = default;

bool RuleEngine::Init()
{
    // TODO: load from file and also using the location near GView or from settings
    std::ifstream analysis_engine("AnalysisEngine.json");
    if (!analysis_engine.is_open())
        return false;
    json analysis_data = json::parse(analysis_engine, nullptr, false);
    if (analysis_data.is_discarded())
        return false;
    try {
        predicates.ExtractPredicates(analysis_data, "predicates");
        actions.ExtractPredicates(analysis_data, "actions");

        auto ctx = std::make_tuple<SpecificationStorage<PredId, PredicateSpecification>*, SpecificationStorage<ActId, PredicateSpecification>*>(
              &predicates, &actions);

        SpecificationStorage<RuleId, RuleSpecification> rules_specification_storage;
        rules_specification_storage.ExtractPredicates(analysis_data, "rules", &ctx);
        for (auto& rule : rules_specification_storage.id_to_specification) {
            auto clause_literals = std::vector<PredLiteral>{};
            clause_literals.reserve(rule.second.clauses.size());
            for (auto& clause : rule.second.clauses) {
                auto clause_stripped = std::string_view(clause);
                bool negated         = false;
                if (clause_stripped.starts_with("NOT ")) {
                    clause_stripped.remove_prefix(4);
                    negated = true;
                }
                auto pred_id = predicates.name_to_id.find(clause_stripped);
                if (pred_id == predicates.name_to_id.end())
                    throw std::runtime_error(std::format("RuleEngine::Init: rule '{}' uses unknown predicate '{}'", rule.second.name, clause_stripped));
                clause_literals.push_back(PredLiteral{ pred_id->second, negated });
            }
            auto rule_clause = clause(clause_literals);

            std::vector<PredOrAction> results_parsed;
            results_parsed.reserve(rule.second.results.size());
            for (auto& result : rule.second.results) {
                auto pred_id = predicates.name_to_id.find(result);
                if (pred_id != predicates.name_to_id.end()) {
                    PredOrAction poa;
                    poa.type         = PredOrAction::PredOrActionType::Predicate;
                    poa.data.pred_id = pred_id->second;
                    results_parsed.push_back(poa);
                    continue;
                }
                auto act_id = actions.name_to_id.find(result);
                if (act_id != actions.name_to_id.end()) {
                    PredOrAction poa;
                    poa.type           = PredOrAction::PredOrActionType::Action;
                    poa.data.action_id = act_id->second;
                    results_parsed.push_back(poa);
                    continue;
                }
                throw std::runtime_error(std::format("RuleEngine::Init: rule '{}' uses unknown predicate/action '{}'", rule.second.name, result));
            }

            Rule converted_rule = {
                rule.first, rule.second.name, rule_clause, results_parsed, rule.second.confidence, rule.second.variable_mapping, rule.second.explanation
            };
            register_rule(converted_rule);
            rules.name_to_id[rule.second.name]    = rule.first;
            rules.id_to_specification[rule.first] = converted_rule;
        }
        rules.next_available_id = rules_specification_storage.next_available_id;
        engineWindow            = { new AnalysisEngineWindow(this) };

        return true;
    } catch (const std::exception& e) {
        AppCUI::Dialogs::MessageBox::ShowError("Found err", e.what());
        return false;
    }
}

bool RuleEngine::SubmitFact(const Fact& fact)
{
    auto pred_id = fact.atom.pred;
    auto pred_specif_it = predicates.id_to_specification.find(pred_id);
    if (pred_specif_it == predicates.id_to_specification.end())
        return false;
    if (pred_specif_it->second.arguments.size() > fact.atom.args.size())
        return false;
    std::unordered_set<std::string> expected_args = {};
    expected_args.insert(pred_specif_it->second.arguments.begin(), pred_specif_it->second.arguments.end());
    for (const auto& arg : fact.atom.args) {
        if (!expected_args.contains(arg.name))
            return false;
    }
    return set_fact(fact).ok;
}

ActId RuleEngine::GetActId(std::string_view name) const
{
    auto it = actions.name_to_id.find(name);
    if (it != actions.name_to_id.end())
        return it->second;
    return INVALID_ACT_ID;
}

PredId RuleEngine::GetPredId(std::string_view name) const
{
    auto it = predicates.name_to_id.find(name);
    if (it != predicates.name_to_id.end())
        return it->second;
    return INVALID_ACT_ID;
}

std::string_view RuleEngine::GetPredName(PredId p) const
{
    if (p == INVALID_ACT_ID)
        return "";
    auto it = predicates.id_to_specification.find(p);
    if (it != predicates.id_to_specification.end())
        return it->second.name;
    return "";
}

std::string_view RuleEngine::GetActName(ActId a) const
{
    if (a == INVALID_ACT_ID)
        return "";
    auto it = actions.id_to_specification.find(a);
    if (it != actions.id_to_specification.end())
        return it->second.name;
    return "";
}

void RuleEngine::ShowAnalysisEngineWindow()
{
    engineWindow->BeforeOpen();
    engineWindow->Show();
}

bool RuleEngine::RegisterActionTrigger(ActId action, Reference<RuleTriggerInterface> trigger)
{
    if (action == INVALID_ACT_ID || trigger == nullptr || !actions.id_to_specification.contains(action))
        return false;
    action_handlers[action].push_back(trigger);
    return true;
}

Subject RuleEngine::GetSubjectForNewWindow(Object::Type objectType)
{
    Subject::SubjectType type = Subject::SubjectType::None;
    switch (objectType) {
    case Object::Type::File:
        type = Subject::SubjectType::File;
        break;
    case Object::Type::Process:
        type = Subject::SubjectType::Process;
        break;
    case Object::Type::Folder:
        type = Subject::SubjectType::File; // Treat folders as files for now
        break;
    case Object::Type::MemoryBuffer:
        type = Subject::SubjectType::File; // Treat memory buffers as files for now
        break;
    default:
        assert(false);
        // Should be implemented -> report to @rzaharia
        break;
    }
    return { type, next_available_subject++ };
}

void RuleEngine::RegisterSubjectWithParent(const Subject& currentWindow, Reference<Subject> parentWindow)
{
    const bool already_inside = subjects_hierarchy.contains(currentWindow.value);
    assert(!already_inside); // Should not re-register existing subject

    SubjectParentInfo info;
    info.direct_parent                      = parentWindow ? parentWindow->value : 1;
    info.main_parent                        = parentWindow ? FindMainParent(parentWindow->value) : 1;
    subjects_hierarchy[currentWindow.value] = info;
    windows[currentWindow.value]            = currentWindow;
}

uint64 RuleEngine::FindMainParent(uint64 current_subject)
{
    uint64 subject = current_subject;
    while (true) {
        auto it = subjects_hierarchy.find(subject);
        if (it == subjects_hierarchy.end())
            break;
        if (it->first == 1)
            break;
        subject = it->first;
    }
    return subject;
}

// Set a fact; threadsafe. Returns Status.
Status RuleEngine::set_fact(const Fact& f) noexcept
{
    return impl_->st.facts.add(f);
}

// Set a fact; threadsafe. Returns Status.
Status RuleEngine::set_fact(PredId p, const Subject& s, std::string source) noexcept
{
    Fact f;
    f.atom.pred    = p;
    f.atom.subject = s;
    f.source       = std::move(source);
    f.time         = now();
    return set_fact(f);
}

// Evaluate rules for a given subject; return emitted suggestions
std::vector<Suggestion> RuleEngine::evaluate(const Subject& s) noexcept
{
    std::vector<Suggestion> out;
    try {
        std::unique_lock lk(impl_->st.mu_rules, std::defer_lock);
        lk.lock();
        for (const auto& r : impl_->st.rules) {
            std::vector<Reference<const Fact>> matched_facts;
            if (impl_->holds(r.clause, s, matched_facts)) {
                if (impl_->st.bus.should_emit(r.results, r.cooldown, s)) {
                    Suggestion sug;
                    sug.subject    = s;
                    sug.results    = r.results;
                    sug.confidence = r.confidence;
                    sug.message    = FillRuleTemplate(r, matched_facts);
                    // sug.cooldown     = r.cooldown;
                    sug.last_emitted = now();
                    sug.rule_id      = r.id;
                    current_suggestions.push_back(sug);
                    out.push_back(std::move(sug));
                }
            }
        }
        return out;
    } catch (...) {
        out.clear();
        return out;
    }
}

Status RuleEngine::register_rule(const Rule& r) noexcept
{
    try {
        std::unique_lock lk(impl_->st.mu_rules);
        impl_->st.rules.push_back(r);
        return Status::OK();
    } catch (const std::exception& e) {
        const auto err = std::format("register_rule: {}", e.what());
        return Status::Error(err);
    } catch (...) {
        return Status::Error("register_rule: unknown");
    }
}

std::string RuleEngine::GetRulePredicates(RuleId rule_id) const
{
    // TODO --> implement this properly
    // std::shared_lock lk(impl_->st.mu_rules);

    const auto& rule_it = rules.id_to_specification.find(rule_id);
    if (rule_it == rules.id_to_specification.end()) {
        Dialogs::MessageBox::ShowError("Err", "Invalid rule, not found!");
        return "";
    }
    auto& r = rule_it->second;
    LocalString<1024> buf = {};
    bool first_add        = true;
    const char* and_str   = "";
    try {
        for (const auto& L : r.clause.all_of) {
            auto pred_name = GetPredName(L.pred);
            buf.AddFormat(" %s%s%.*s", and_str, L.negated ? "NOT-" : "", pred_name.size(), pred_name.data());
            if (first_add) {
                first_add = false;
                and_str   = "AND ";
            }
        }
        return std::string(buf.GetText());
    } catch (...) {
        return "";
    }
    return "";
}

bool RuleEngine::TryExecuteSuggestion(uint32 index, bool& shouldCloseAnalysisWindow)
{
    if (current_suggestions.empty())
        return false;
    if (index >= current_suggestions.size())
        return false;
    const auto& s = current_suggestions[index];

    std::vector<Reference<RuleTriggerInterface>> handlers;
    for (const auto& res : s.results) {
        if (res.type == PredOrAction::PredOrActionType::Action) {
            auto it = action_handlers.find(res.data.action_id);
            if (it != action_handlers.end()) {
                for (auto& h : it->second) {
                    if (h.IsValid())
                        handlers.push_back(h);
                }
            }
        }
    }

    /*if (handlers.empty())//TODO: consider reenable this check?
        return true; */

    bool final_delete_rule = true;
    for (auto& h : handlers) {
        if (!h.IsValid())
            continue;
        bool delete_rule = true;
        h->OnRuleTrigger(s, delete_rule, shouldCloseAnalysisWindow);
        final_delete_rule = final_delete_rule && delete_rule;
    }
    if (final_delete_rule) {
        current_suggestions.erase(current_suggestions.begin() + index);
    }
    return true;
}

} // namespace GView::Components::AnalysisEngine
