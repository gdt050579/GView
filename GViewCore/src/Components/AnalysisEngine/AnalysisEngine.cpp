#include "AnalysisEngine.hpp"
#include "AnalysisEngineWindow.hpp"
#include "KnowledgeBase.hpp"
#include "PatternMatcher.hpp"

#include <cassert>
#include <algorithm>
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <unordered_set>

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

namespace
{
    class SuggestionBus
    {
      public:
        [[nodiscard]] bool ShouldEmit(
              RuleId rule_id, const std::vector<PredOrAction>& results, std::chrono::milliseconds cooldown, const Subject& s) noexcept
        {
            try {
                const auto key = MakeKey(rule_id, results, s);
                const auto t   = now();
                std::unique_lock lk(mu_);
                auto it = last_.find(key);
                if (it == last_.end()) {
                    last_[key] = t;
                    return true;
                }
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t - it->second);
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
        using Key = std::string;
        static Key MakeKey(RuleId rule_id, const std::vector<PredOrAction>& results, const Subject& s)
        {
            LocalString<256> buffer;
            buffer.AddFormat("r%ull#", rule_id);
            for (const auto& res : results) {
                if (res.type == PredOrAction::PredOrActionType::Action)
                    buffer.AddFormat("a%ull#", res.data.action_id);
                else
                    buffer.AddFormat("p%ull#", res.data.pred_id);
            }
            buffer.AddFormat("%u#%ull", static_cast<uint32>(s.kind), s.value);
            return { buffer.GetText() };
        }
        std::mutex mu_;
        std::unordered_map<Key, TimePoint> last_;
    };

    [[nodiscard]] bool IsAssertionRule(const Rule& rule) noexcept
    {
        if (rule.head.empty())
            return false;
        return rule.head[0].type == PredOrAction::PredOrActionType::Predicate;
    }
} // anonymous namespace

struct RuleEngine::Impl {
    KnowledgeBase knowledge;
    SuggestionBus bus;
    std::vector<Rule> all_rules;
    std::vector<Rule> assertion_rules;
    std::vector<Rule> action_rules;
    std::mutex mu_rules;
};

RuleEngine::RuleEngine() : engineWindow(nullptr), impl_(std::make_unique<Impl>())
{
    current_suggestions.reserve(8);
}

RuleEngine::~RuleEngine() noexcept = default;

bool RuleEngine::Init()
{
    AnalysisEngineConfig::Initialize(config_);

    std::ifstream analysis_engine("AnalysisEngine.json");
    if (!analysis_engine.is_open()) {
        auto current_app_path = AppCUI::OS::GetCurrentApplicationPath();
        if (!current_app_path.has_filename())
            return false;
        current_app_path = current_app_path.remove_filename();
        current_app_path /= "AnalysisEngine.json";
        analysis_engine.open(current_app_path);
        if (!analysis_engine.is_open())
            return false;
    }
    json analysis_data = json::parse(analysis_engine, nullptr, false);
    if (analysis_data.is_discarded())
        return false;
    try {
        predicates.ExtractPredicates(analysis_data, "predicates");
        actions.ExtractPredicates(analysis_data, "actions");

        for (const auto& pair_names : config_.contradiction_names) {
            ContradictionPair pair;
            auto a_it = predicates.name_to_id.find(pair_names.predicate_a);
            auto b_it = predicates.name_to_id.find(pair_names.predicate_b);
            if (a_it != predicates.name_to_id.end() && b_it != predicates.name_to_id.end()) {
                pair.predicate_a = a_it->second;
                pair.predicate_b = b_it->second;
                config_.contradictions.push_back(pair);
            }
        }

        if (analysis_data.contains("contradictions") && analysis_data["contradictions"].is_array()) {
            for (const auto& entry : analysis_data["contradictions"]) {
                if (!entry.is_array() || entry.size() != 2)
                    continue;
                const auto a_name = entry[0].get<std::string>();
                const auto b_name = entry[1].get<std::string>();
                auto a_it         = predicates.name_to_id.find(a_name);
                auto b_it         = predicates.name_to_id.find(b_name);
                if (a_it != predicates.name_to_id.end() && b_it != predicates.name_to_id.end()) {
                    config_.contradictions.push_back({ a_it->second, b_it->second });
                }
            }
        }

        auto ctx = std::make_tuple<SpecificationStorage<PredId, PredicateSpecification>*, SpecificationStorage<ActId, PredicateSpecification>*>(
              &predicates, &actions);

        SpecificationStorage<RuleId, RuleSpecification> rules_specification_storage;
        rules_specification_storage.ExtractPredicates(analysis_data, "rules", &ctx);
        for (auto& rule : rules_specification_storage.id_to_specification) {
            auto clause_literals = std::vector<PredLiteral>{};
            clause_literals.reserve(rule.second.body.size());
            for (auto& clause : rule.second.body) {
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
            results_parsed.reserve(rule.second.head.size());
            for (auto& result : rule.second.head) {
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
            const bool is_assertion = IsAssertionRule(converted_rule);
            register_rule(converted_rule, is_assertion);
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

void RuleEngine::CheckContradictions(const Fact& fact) const
{
    for (const auto& pair : config_.contradictions) {
        const PredId other =
              (fact.atom.pred == pair.predicate_a) ? pair.predicate_b :
              (fact.atom.pred == pair.predicate_b) ? pair.predicate_a :
                                                     INVALID_PRED_ID;
        if (other == INVALID_PRED_ID)
            continue;
        if (impl_->knowledge.Exists(other, fact.atom.subject))
            throw std::logic_error("Knowledge base contradiction detected (Gamma |- False)");
    }
}

void RuleEngine::RecordInitialDerivation(const Fact& fact)
{
    const auto key = MakeFactKey(fact);
    if (impl_->knowledge.GetDerivationIndex().contains(key))
        return;
    auto node                 = std::make_shared<DerivationNode>();
    node->derived_key         = key;
    node->source_type         = DerivationSourceType::InitialExtraction;
    impl_->knowledge.GetDerivationIndex()[key] = std::move(node);
}

void RuleEngine::MaybeRunClosureAfterFact()
{
    if (config_.closure_mode == ClosureMode::Auto) {
        const auto status = ComputeAssertionClosure();
        if (!status.ok)
            AppCUI::Dialogs::MessageBox::ShowError("Closure error", status.message);
    }
}

bool RuleEngine::SubmitFact(const Fact& fact)
{
    auto pred_id        = fact.atom.pred;
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

    try {
        CheckContradictions(fact);
    } catch (const std::logic_error& e) {
        AppCUI::Dialogs::MessageBox::ShowError("Consistency violation", e.what());
        return false;
    }

    if (!set_fact(fact).ok)
        return false;

    RecordInitialDerivation(fact);
    MaybeRunClosureAfterFact();

    if constexpr (DISPLAY_FACTS_AS_ANALYSIS_NOTES) {
        auto fact_message = FormatFactMessage(fact, pred_specif_it->second);
        AddAnalysisNotes(fact.atom.subject, std::move(fact_message));
    }
    return true;
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
    return INVALID_PRED_ID;
}

std::string_view RuleEngine::GetPredName(PredId p) const
{
    if (p == INVALID_PRED_ID)
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

std::vector<bool> RuleEngine::RegisterActionTrigger(const std::vector<ActId>& action_ids, Reference<RuleTriggerInterface> trigger)
{
    std::vector<bool> results;
    results.resize(action_ids.size());
    for (size_t i = 0; i < action_ids.size(); i++) {
        const auto& action = action_ids[i];
        if (action == INVALID_ACT_ID || trigger == nullptr || !actions.id_to_specification.contains(action)) {
            results[i] = false;
            continue;
        }
        action_handlers[action].push_back(trigger);
        results[i] = true;
    }
    return results;
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
        type = Subject::SubjectType::File;
        break;
    case Object::Type::MemoryBuffer:
        type = Subject::SubjectType::File;
        break;
    default:
        assert(false);
        break;
    }
    return { type, next_available_subject++ };
}

void RuleEngine::RegisterSubjectWithParent(const Subject& currentWindowSubject, Reference<Window> currentWindow, Reference<Subject> parentWindow)
{
    engineWindow->RegisterSubjectWithParent(currentWindowSubject, currentWindow, parentWindow);
}

void RuleEngine::AddAnalysisNotes(const Subject& currentWindow, std::string data)
{
    engineWindow->AddAnalysisNotes(currentWindow, std::move(data));
}

uint64 RuleEngine::FindMainParent(uint64 current_subject)
{
    return engineWindow->FindMainParent(current_subject);
}

Status RuleEngine::set_fact(const Fact& f) noexcept
{
    return impl_->knowledge.Add(f);
}

Status RuleEngine::set_fact(PredId p, const Subject& s, std::string source) noexcept
{
    Fact f;
    f.atom.pred    = p;
    f.atom.subject = s;
    f.source       = std::move(source);
    f.time         = now();
    return set_fact(f);
}

std::span<const Fact> RuleEngine::GetFactsSpan() const noexcept
{
    return impl_->knowledge.FactsSpan();
}

std::shared_ptr<const SnapshotNode> RuleEngine::CurrentSnapshot() const noexcept
{
    return impl_->knowledge.CurrentSnapshot();
}

std::span<const StateTransition> RuleEngine::DisclosureTraceSpan() const noexcept
{
    return impl_->knowledge.GetDisclosureTrace().TraceSpan();
}

const DerivationIndex& RuleEngine::GetDerivationIndex() const noexcept
{
    return impl_->knowledge.GetDerivationIndex();
}

Status RuleEngine::ComputeAssertionClosure() noexcept
{
    // Theory Note: max_closure_iterations caps the fixed-point loop; cyclic rule sets would
    // otherwise fail to terminate, restricting theoretical Cl_R(Gamma) completeness.
    uint32 iterations = 0;
    bool changed      = true;

    while (changed && iterations < config_.max_closure_iterations) {
        changed = false;
        ++iterations;

        std::unique_lock lk(impl_->mu_rules);

        std::vector<Subject> subjects;
        subjects.reserve(16);
        for (const auto& fact : impl_->knowledge.FactsSpan()) {
            const auto found = std::find_if(subjects.begin(), subjects.end(), [&](const Subject& s) {
                return s.kind == fact.atom.subject.kind && s.value == fact.atom.subject.value;
            });
            if (found == subjects.end())
                subjects.push_back(fact.atom.subject);
        }

        for (const auto& rule : impl_->assertion_rules) {
            for (const auto& subject : subjects) {
                std::vector<Reference<const Fact>> matched_facts;
                if (!PatternMatcher::Holds(rule.body, subject, impl_->knowledge, matched_facts))
                    continue;

                for (const auto& head : rule.head) {
                    if (head.type != PredOrAction::PredOrActionType::Predicate)
                        continue;

                    Fact inferred;
                    inferred.atom.pred    = head.data.pred_id;
                    inferred.atom.subject = subject;
                    inferred.source       = "inference";
                    inferred.details      = rule.explanation;
                    inferred.time         = now();

                    const auto key = MakeFactKey(inferred);
                    if (impl_->knowledge.HasFactKey(key))
                        continue;

                    try {
                        CheckContradictions(inferred);
                    } catch (const std::logic_error& e) {
                        return Status::Error(e.what());
                    }

                    if (!impl_->knowledge.Add(inferred).ok)
                        continue;

                    auto node              = std::make_shared<DerivationNode>();
                    node->derived_key      = key;
                    node->source_type      = DerivationSourceType::Rule;
                    node->source_rule_id   = rule.id;
                    for (auto& mf : matched_facts) {
                        if (!mf.IsValid())
                            continue;
                        auto dep         = std::make_shared<DerivationNode>();
                        dep->derived_key = MakeFactKey(static_cast<const Fact&>(mf));
                        dep->source_type = DerivationSourceType::InitialExtraction;
                        node->dependencies.push_back(std::move(dep));
                    }
                    impl_->knowledge.GetDerivationIndex()[key] = std::move(node);
                    changed = true;

                    if constexpr (DISPLAY_FACTS_AS_ANALYSIS_NOTES) {
                        const auto pred_it = predicates.id_to_specification.find(inferred.atom.pred);
                        if (pred_it != predicates.id_to_specification.end()) {
                            auto msg = FormatFactMessage(inferred, pred_it->second);
                            AddAnalysisNotes(inferred.atom.subject, std::move(msg));
                        }
                    }
                }
            }
        }
    }

    if (iterations >= config_.max_closure_iterations && changed)
        return Status::Error("Assertion closure reached max iteration limit");

    return Status::OK();
}

Status RuleEngine::RunClosure() noexcept
{
    return ComputeAssertionClosure();
}

std::vector<Suggestion> RuleEngine::evaluate(const Subject& s) noexcept
{
    if (config_.closure_mode == ClosureMode::Manual) {
        const auto status = RunClosure();
        (void)status;
    }

    std::vector<Suggestion> out;
    try {
        std::unique_lock lk(impl_->mu_rules);
        for (const auto& r : impl_->action_rules) {
            std::vector<Reference<const Fact>> matched_facts;
            if (!PatternMatcher::Holds(r.body, s, impl_->knowledge, matched_facts))
                continue;
            if (!impl_->bus.ShouldEmit(r.id, r.head, r.cooldown, s))
                continue;

            Suggestion sug;
            sug.subject    = s;
            sug.results    = r.head;
            sug.confidence = r.confidence;
            sug.message    = FillRuleTemplate(r, matched_facts);
            sug.last_emitted = now();
            sug.rule_id      = r.id;
            sug.id           = next_suggestion_id++;
            current_suggestions.push_back(sug);
            out.push_back(std::move(sug));
        }
        return out;
    } catch (...) {
        out.clear();
        return out;
    }
}

Status RuleEngine::register_rule(const Rule& r, bool is_assertion_rule) noexcept
{
    try {
        std::unique_lock lk(impl_->mu_rules);
        impl_->all_rules.push_back(r);
        if (is_assertion_rule)
            impl_->assertion_rules.push_back(r);
        else
            impl_->action_rules.push_back(r);
        return Status::OK();
    } catch (const std::exception& e) {
        return Status::Error(std::format("register_rule: {}", e.what()));
    } catch (...) {
        return Status::Error("register_rule: unknown");
    }
}

std::string RuleEngine::GetRulePredicates(RuleId rule_id) const
{
    std::lock_guard lk(impl_->mu_rules);

    const auto& rule_it = rules.id_to_specification.find(rule_id);
    if (rule_it == rules.id_to_specification.end())
        return "";

    const auto& r     = rule_it->second;
    LocalString<1024> buf = {};
    bool first_add    = true;
    const char* and_str = "";
    for (const auto& L : r.body.all_of) {
        auto pred_name = GetPredName(L.pred);
        buf.AddFormat(" %s%s%.*s", and_str, L.negated ? "NOT-" : "", static_cast<int>(pred_name.size()), pred_name.data());
        if (first_add) {
            first_add = false;
            and_str   = "AND ";
        }
    }
    return std::string(buf.GetText());
}

bool RuleEngine::TryExecuteSuggestionByArrayIndex(uint32 index, bool& shouldCloseAnalysisWindow)
{
    if (current_suggestions.empty() || index >= current_suggestions.size())
        return false;
    const auto& s = current_suggestions[index];

    std::optional<GroundAction> ground_action;
    for (const auto& res : s.results) {
        if (res.type == PredOrAction::PredOrActionType::Action) {
            ground_action = GroundAction{ res.data.action_id, {} };
            break;
        }
    }

    impl_->knowledge.BeginTransitionCollection();
    const auto from_snapshot = impl_->knowledge.CurrentSnapshot();

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

    bool final_delete_rule = true;
    for (auto& h : handlers) {
        if (!h.IsValid())
            continue;
        bool delete_rule = true;
        h->OnRuleTrigger(s, delete_rule, shouldCloseAnalysisWindow);
        final_delete_rule = final_delete_rule && delete_rule;
    }

    impl_->knowledge.EndTransitionCollection();
    auto new_indices = impl_->knowledge.StealCollectedIndices();
    impl_->knowledge.RecordTransition(from_snapshot, std::move(ground_action), std::move(new_indices));
    MaybeRunClosureAfterFact();

    if (final_delete_rule)
        current_suggestions.erase(current_suggestions.begin() + index);
    return true;
}

bool RuleEngine::TryExecuteSuggestionBySuggestionId(SuggestionId id, bool& shouldCloseAnalysisWindow)
{
    for (uint32 i = 0; i < current_suggestions.size(); i++) {
        if (current_suggestions[i].id == id)
            return TryExecuteSuggestionByArrayIndex(i, shouldCloseAnalysisWindow);
    }
    return false;
}

Reference<const Suggestion> RuleEngine::GetSuggestionById(SuggestionId id) const
{
    for (const auto& s : current_suggestions) {
        if (s.id == id)
            return &s;
    }
    return nullptr;
}

} // namespace GView::Components::AnalysisEngine
