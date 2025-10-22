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
        bool should_emit(const Action& a, std::chrono::milliseconds cooldown) noexcept
        {
            try {
                auto key = make_key(a);
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
        static Key make_key(const Action& a)
        {
            // cheap serialization
            std::string s = std::to_string(static_cast<unsigned>(a.key)) + "#" + std::to_string((uint32_t) a.subject.kind);
            if (a.subject.kind != Subject::SubjectType::None)
                s += ":" + std::to_string(a.subject.value);
            return s;
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

    bool holds(const ConjClause& c, const Subject& s) const noexcept
    {
        const auto t_now = now();
        for (const auto& L : c.all_of) {
            const bool present = st.facts.exists(L.pred, s);
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

        auto ctx = std::make_tuple<SpecificationStorage<PredId, PredicateSpecification>*, SpecificationStorage<ActId, PredicateSpecification>*>(&predicates, &actions);
        rules.ExtractPredicates(analysis_data, "rules", &ctx);
        auto status = install_builtin_rules();
        if (!status.ok) // TODO: show the error message somewhere
            return false;

        engineWindow = { new AnalysisEngineWindow(this) };

        return true;
    }
    catch (const std::exception& e) {
        AppCUI::Dialogs::MessageBox::ShowError("Found err", e.what());
        return false;
    }
}

bool RuleEngine::SubmitFact(const Fact& fact)
{
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
            if (impl_->holds(r.clause, s)) {
                if (impl_->st.bus.should_emit(r.action, r.cooldown)) {
                    Suggestion sug;
                    sug.action     = r.action;
                    sug.confidence = r.confidence;
                    sug.message    = r.message;
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

Status RuleEngine::install_builtin_rules() noexcept
{
    // TODO: to be replaced with the file that contains the comprehensive rulebook
    try {
        //auto R = [&](std::string id,
        //             ConjClause c,
        //             ActDefaultValues ak,
        //             Confidence confidence,
        //             std::string msg,
        //             std::chrono::milliseconds cd = std::chrono::minutes(30)) {
        //    Rule r;
        //    r.id         = std::move(id);
        //    r.clause     = std::move(c);
        //    r.action     = { (ActId) ak, Subject{} };
        //    r.confidence = confidence;
        //    r.message    = std::move(msg);
        //    // r.cooldown = cd;
        //    return register_rule(r);
        //};
        //auto C = [&](std::initializer_list<Literal> lits, int win_ms = 0) { return clause(lits, std::chrono::milliseconds{ win_ms }); };

        //// File-only
        //R("F-001",
        //  C({ lit(PredDefaultValues::IsWord), lit(PredDefaultValues::HasMacros) }),
        //  ActDefaultValues::ViewMacros,
        //  70,
        //  "Macros present. Open Macro Viewer?");
        //R("F-002",
        //  C({ lit(PredDefaultValues::IsWord), lit(PredDefaultValues::HasMacroObfuscation) }),
        //  ActDefaultValues::DeobfuscateVBA,
        //  70,
        //  "Obfuscated macros detected. Deobfuscate now?");
        //R("F-003",
        //  C({ lit(PredDefaultValues::IsWord), lit(PredDefaultValues::ContainsExternalTemplateRef) }),
        //  ActDefaultValues::ViewExternalTemplates,
        //  40,
        //  "External template reference. Inspect RELs?");
        //R("F-004",
        //  C({ lit(PredDefaultValues::IsExcel), lit(PredDefaultValues::HasXlm4Macro) }),
        //  ActDefaultValues::ViewXlmSheets,
        //  70,
        //  "Excel 4.0 macro sheet present. Review?");
        //R("F-005",
        //  C({ lit(PredDefaultValues::IsExcel), lit(PredDefaultValues::HasHiddenSheets) }),
        //  ActDefaultValues::ViewHiddenSheets,
        //  40,
        //  "Hidden sheets found. Show list?");
        //R("F-010",
        //  C({ lit(PredDefaultValues::IsPdf), lit(PredDefaultValues::PdfHasJavaScript) }),
        //  ActDefaultValues::ViewPdfJavaScript,
        //  70,
        //  "PDF has JavaScript. Inspect code?");
        //R("F-011",
        //  C({ lit(PredDefaultValues::IsPdf), lit(PredDefaultValues::PdfHasOpenAction) }),
        //  ActDefaultValues::ViewPdfObjects,
        //  70,
        //  "Auto-action triggers on open. Inspect objects?");
        //R("F-020",
        //  C({ lit(PredDefaultValues::IsScript), lit(PredDefaultValues::HasObfuscatedStrings) }),
        //  ActDefaultValues::BeautifyScript,
        //  70,
        //  "Obfuscated script. Beautify for review?");
        //R("F-030",
        //  C({ lit(PredDefaultValues::IsPe), lit(PredDefaultValues::HasHighEntropy) }),
        //  ActDefaultValues::IdentifyPacker,
        //  40,
        //  "High entropy suggests packing. Identify packer?");
        //R("F-031",
        //  C({ lit(PredDefaultValues::IsPe), lit(PredDefaultValues::ContainsEmbeddedExecutable) }),
        //  ActDefaultValues::ViewResources,
        //  40,
        //  "Embedded payload(s) detected. Inspect resources?");
        //R("F-040",
        //  C({ lit(PredDefaultValues::IsArchive), lit(PredDefaultValues::ArchiveIsPasswordProtected) }),
        //  ActDefaultValues::SafeExtract,
        //  40,
        //  "Password-protected archive. Safe-extract to sandbox?");
        //R("F-041",
        //  C({ lit(PredDefaultValues::IsArchive), lit(PredDefaultValues::ArchiveContainsExecutable) }),
        //  ActDefaultValues::ViewArchiveManifest,
        //  40,
        //  "Executable(s) inside archive. Review manifest?");
        //R("F-050", C({ lit(PredDefaultValues::MarkOfTheWeb) }), ActDefaultValues::ViewMOTW, 10, "Internet-origin marker present. Inspect source zone?");
        //R("F-051",
        //  C({ lit(PredDefaultValues::HashInThreatIntel) }),
        //  ActDefaultValues::ViewThreatIntelHits,
        //  100,
        //  "Known-bad hash in intel. Review details now.",
        //  std::chrono::minutes(5));

        //// User-only
        //R("U-100",
        //  C({ lit(PredDefaultValues::Opened), lit(PredDefaultValues::ViewedHashes, true) }),
        //  ActDefaultValues::ComputeHashes,
        //  10,
        //  "Compute hashes for correlation & TI lookups?");
        //R("U-101",
        //  C({ lit(PredDefaultValues::ComputedHashes), lit(PredDefaultValues::QueriedThreatIntel, true) }),
        //  ActDefaultValues::QueryThreatIntel,
        //  10,
        //  "Check reputation across intel sources?");
        //R("U-102",
        //  C({ lit(PredDefaultValues::Opened), lit(PredDefaultValues::ViewedStrings, true) }),
        //  ActDefaultValues::ViewStrings,
        //  10,
        //  "Review strings for URLs and IOCs?");
        //R("U-120",
        //  C({ lit(PredDefaultValues::Opened), lit(PredDefaultValues::OpenedSafely, true), lit(PredDefaultValues::IsWord) }),
        //  ActDefaultValues::OpenInSafeView,
        //  70,
        //  "Use protected view to avoid executing active content.");
        //R("U-121",
        //  C({ lit(PredDefaultValues::Opened), lit(PredDefaultValues::SwitchedToIsolatedNetwork, true), lit(PredDefaultValues::MarkOfTheWeb) }),
        //  ActDefaultValues::SwitchToIsolatedNetwork,
        //  70,
        //  "Switch to isolated/no-Internet sandbox.");
        //R("U-122",
        //  C({ lit(PredDefaultValues::Opened), lit(PredDefaultValues::CreatedSnapshot, true) }),
        //  ActDefaultValues::CreateSnapshot,
        //  10,
        //  "Create VM snapshot before detonation?");

        //// Mixed (subset of comprehensive rulebook)
        //R("M-200",
        //  C({ lit(PredDefaultValues::IsWord), lit(PredDefaultValues::HasMacros), lit(PredDefaultValues::ViewedMacros, true) }),
        //  ActDefaultValues::ViewMacros,
        //  70,
        //  "Macros present. Open Macro Viewer?");
        //R("M-201",
        //  C({ lit(PredDefaultValues::HasMacroObfuscation), lit(PredDefaultValues::DeobfuscatedVBA, true) }),
        //  ActDefaultValues::DeobfuscateVBA,
        //  70,
        //  "Obfuscated macros found. Deobfuscate now?");
        //R("M-202",
        //  C({ lit(PredDefaultValues::HasSuspiciousMacroFunctionCalls), lit(PredDefaultValues::ViewedSuspiciousCalls, true) }),
        //  ActDefaultValues::ViewSuspiciousCalls,
        //  70,
        //  "Suspicious macro APIs detected. Review call list?");
        //R("M-203",
        //  C({ lit(PredDefaultValues::ContainsExternalTemplateRef), lit(PredDefaultValues::ViewedExternalTemplateRels, true) }),
        //  ActDefaultValues::ViewExternalTemplates,
        //  40,
        //  "Remote template reference. Inspect RELs?");

        //R("M-210",
        //  C({ lit(PredDefaultValues::ContainsBase64Blobs), lit(PredDefaultValues::DecodedBase64Blobs, true) }),
        //  ActDefaultValues::DecodeBase64,
        //  40,
        //  "Base64 blobs detected. Decode for payloads?");
        //R("M-211",
        //  C({ lit(PredDefaultValues::ContainsHexBlobs), lit(PredDefaultValues::DecodedHexBlobs, true) }),
        //  ActDefaultValues::DecodeHex,
        //  10,
        //  "Hex blobs present. Decode now?");
        //R("M-212",
        //  C({ lit(PredDefaultValues::ContainsUrl), lit(PredDefaultValues::ExtractedUrls, true) }),
        //  ActDefaultValues::ExtractUrls,
        //  10,
        //  "Extract URLs for pivoting & blocking?");
        //R("M-213",
        //  C({ lit(PredDefaultValues::ContainsEmbeddedArchive), lit(PredDefaultValues::CarvedEmbeddedFiles, true) }),
        //  ActDefaultValues::CarveEmbedded,
        //  40,
        //  "Embedded archive(s) found. Carve safely?");

        //R("M-220",
        //  C({ lit(PredDefaultValues::IsPe), lit(PredDefaultValues::ViewedImports, true) }),
        //  ActDefaultValues::ViewImports,
        //  10,
        //  "Review imported APIs for intent?");
        //R("M-221",
        //  C({ lit(PredDefaultValues::IsPe), lit(PredDefaultValues::HasHighEntropy), lit(PredDefaultValues::RanPackerId, true) }),
        //  ActDefaultValues::IdentifyPacker,
        //  40,
        //  "Likely packed. Identify packer?");
        //R("M-223",
        //  C({ lit(PredDefaultValues::IsPe), lit(PredDefaultValues::ViewedOverlay, true) }),
        //  ActDefaultValues::ViewOverlay,
        //  10,
        //  "Overlay data present. Inspect trailing bytes?");

        //R("M-230",
        //  C({ lit(PredDefaultValues::TriesToAccessTheInternet), lit(PredDefaultValues::ViewedNetworkBehavior, true) }),
        //  ActDefaultValues::ViewNetwork,
        //  70,
        //  "Outbound connections observed. Review endpoints?");
        //R("M-231",
        //  C({ lit(PredDefaultValues::BeaconingPattern), lit(PredDefaultValues::ResolvedDomains, true) }),
        //  ActDefaultValues::ViewDnsQueries,
        //  70,
        //  "Beaconing detected. Review DNS queries/domains?");
        //R("M-232",
        //  C({ lit(PredDefaultValues::UsesHTTPSRequests), lit(PredDefaultValues::UsesSelfSignedTls), lit(PredDefaultValues::ViewedTlsCertificates, true) }),
        //  ActDefaultValues::ViewTlsCertificates,
        //  70,
        //  "Self-signed/invalid TLS. Inspect certificate chain?");
        //R("M-233",
        //  C({ lit(PredDefaultValues::WritesToTempExecutable), lit(PredDefaultValues::ViewedFileSystemActivity, true) }),
        //  ActDefaultValues::ViewFileWrites,
        //  70,
        //  "New executable(s) in temp. Review drops?");
        //R("M-234",
        //  C({ lit(PredDefaultValues::DropsAndExecutes), lit(PredDefaultValues::ViewedProcessTree, true) }),
        //  ActDefaultValues::ViewProcessTree,
        //  70,
        //  "Drop-and-run sequence observed. Open process tree?");
        //R("M-235",
        //  C({ lit(PredDefaultValues::CreatesRunKey), lit(PredDefaultValues::ViewedRegistryActivity, true) }),
        //  ActDefaultValues::ViewRegistryChanges,
        //  70,
        //  "Startup persistence detected. Inspect registry changes?");

        //R("M-240",
        //  C({ lit(PredDefaultValues::PersistenceIndicatorsPresent), lit(PredDefaultValues::PersistenceReviewed, true) }),
        //  ActDefaultValues::ViewPersistence,
        //  70,
        //  "Persistence artifacts found. Review them now?");
        //R("M-241",
        //  C({ lit(PredDefaultValues::RequestsUacElevation), lit(PredDefaultValues::ViewedUacEvents, true) }),
        //  ActDefaultValues::ViewUac,
        //  40,
        //  "UAC prompt/elevation attempt. Inspect event details?");
        //R("M-242",
        //  C({ lit(PredDefaultValues::AcquiresSeDebugPrivilege), lit(PredDefaultValues::ViewedTokenPrivileges, true) }),
        //  ActDefaultValues::ViewTokenPrivileges,
        //  70,
        //  "Debug privilege acquired. Review token changes?");

        //R("M-250",
        //  C({ lit(PredDefaultValues::MassFileModification), lit(PredDefaultValues::ViewedEncryptionMonitor, true) }),
        //  ActDefaultValues::MonitorEncryption,
        //  100,
        //  "Rapid file modifications. Start encryption monitor?");
        //R("M-251",
        //  C({ lit(PredDefaultValues::DeletesShadowCopies), lit(PredDefaultValues::ViewedShadowCopyEvents, true) }),
        //  ActDefaultValues::ViewShadowCopyEvents,
        //  70,
        //  "VSS deletion observed. Inspect events?");
        //R("M-252",
        //  C({ lit(PredDefaultValues::DropsRansomNote), lit(PredDefaultValues::ViewedRansomNotes, true) }),
        //  ActDefaultValues::ViewRansomNotes,
        //  70,
        //  "Ransom note artifacts dropped. Open list?");

        //R("M-260",
        //  C({ lit(PredDefaultValues::ReadsManyDocs), lit(PredDefaultValues::ViewedExfilTimeline, true) }),
        //  ActDefaultValues::ViewExfil,
        //  70,
        //  "Mass document reads. Check exfil timeline?");
        //R("M-262",
        //  C({ lit(PredDefaultValues::UploadsLargeVolume), lit(PredDefaultValues::CapturedPcap, true) }),
        //  ActDefaultValues::StartCapturePcap,
        //  70,
        //  "Large outbound traffic. Capture PCAP now?");

        //R("M-270",
        //  C({ lit(PredDefaultValues::ChecksSandboxArtifacts), lit(PredDefaultValues::ViewedAntiVMChecks, true) }),
        //  ActDefaultValues::ViewAntiVM,
        //  40,
        //  "Anti-VM checks observed. Review heuristics?");
        //R("M-271",
        //  C({ lit(PredDefaultValues::DelaysExecutionLong), lit(PredDefaultValues::EnabledTimeWarp, true) }),
        //  ActDefaultValues::EnableTimeWarp,
        //  10,
        //  "Long sleeps observed. Enable time warp?");

        //R("M-280",
        //  C({ lit(PredDefaultValues::IsArchive), lit(PredDefaultValues::ArchiveIsPasswordProtected), lit(PredDefaultValues::ExtractedArchiveSafely, true) }),
        //  ActDefaultValues::SafeExtract,
        //  40,
        //  "Password-protected archive. Extract to sandbox?");
        //R("M-290",
        //  C({ lit(PredDefaultValues::ComputedHashes), lit(PredDefaultValues::QueriedThreatIntel, true), lit(PredDefaultValues::ContainsUrl) }),
        //  ActDefaultValues::QueryThreatIntel,
        //  10,
        //  "Reputation check likely useful here. Query TI?");
        //R("M-292",
        //  C({ lit(PredDefaultValues::IsSuspicious), lit(PredDefaultValues::ExtractedUrls, true) }),
        //  ActDefaultValues::ExtractUrls,
        //  70,
        //  "Extract IOCs to pivot and contain?");
        //R("M-293",
        //  C({ lit(PredDefaultValues::IsSuspicious), lit(PredDefaultValues::ExportedIOCs, true) }),
        //  ActDefaultValues::ExportIOCs,
        //  10,
        //  "Export IOCs (CSV/STIX) for sharing?");
        //R("M-294",
        //  C({ lit(PredDefaultValues::IsMalicious), lit(PredDefaultValues::GeneratedReport, true) }),
        //  ActDefaultValues::GenerateReport,
        //  70,
        //  "Generate a concise report with findings?");

        //// Time-windowed examples
        //R("P-301",
        //  C({ lit(PredDefaultValues::WritesToTempExecutable), lit(PredDefaultValues::DropsAndExecutes) }, 180000),
        //  ActDefaultValues::ViewProcessTree,
        //  70,
        //  "Drop-and-run chain just occurred. Open process graph.");
        //R("P-302",
        //  C({ lit(PredDefaultValues::TriesToAccessTheInternet) }, 600000),
        //  ActDefaultValues::ViewNetwork,
        //  70,
        //  "Recent network activity. Review flows.");
        //R("P-303", C({ lit(PredDefaultValues::CreatesRunKey) }, 600000), ActDefaultValues::ViewPersistence, 70, "New persistence. Review startup artifacts.");

        //R("G-001",
        //  C({ lit(PredDefaultValues::IsPCAP), lit(PredDefaultValues::HasNetworkConnections) }),
        //  ActDefaultValues::CheckConnection,
        //  100,
        //  "The PCAP file has connections. Analyze them?");

        //R("G-002",
        //  C({ /*lit(PredDefaultValues::HasNetworkConnections),*/ lit(PredDefaultValues::HasConnectionWithExecutable) }),
        //  ActDefaultValues::ViewConnectionWithExecutable,
        //  80,
        //  "The PCAP file seems to have connections with executable. Open them?");

        //R("G-003",
        //  C({ /*lit(PredDefaultValues::HasNetworkConnections),*/ lit(PredDefaultValues::HasConnectionWithScript) }),
        //  ActDefaultValues::ViewConnectionWithScript,
        //  80,
        //  "The PCAP file seems to have connections with scripts. Open them?");

        return Status::OK();
    } catch (const std::exception& e) {
        const auto err = std::format("install_builtin_rules: {}", e.what());
        return Status::Error(err);
    } catch (...) {
        return Status::Error("install_builtin_rules: unknown");
    }
}

std::string RuleEngine::GetRulePredicates(std::string_view rule_id) const
{
    // std::shared_lock lk(impl_->st.mu_rules);
    for (const auto& r : impl_->st.rules) {
        if (r.id == rule_id) {
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
        }
    }
    return "";
}

bool RuleEngine::TryExecuteSuggestion(uint32 index, bool& shouldCloseAnalysisWindow)
{
    if (current_suggestions.empty())
        return false;
    if (index >= current_suggestions.size())
        return false;
    auto it = action_handlers.find(current_suggestions[index].action.key);
    if (it == action_handlers.end())
        return true; // no handlers registered
    const auto& s          = current_suggestions[index];
    bool final_delete_rule = true;
    for (auto& h : it->second) {
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
