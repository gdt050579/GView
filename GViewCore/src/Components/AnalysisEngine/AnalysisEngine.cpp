#include "AnalysisEngine.hpp"

#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

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

enum class PredDefaultValues : PredId {
    // Office / Word / Excel / PPT
    IsWord,
    HasMacros,
    ViewedMacros,
    HasMacroObfuscation,
    DeobfuscatedVBA,
    ContainsExternalTemplateRef,
    ViewedExternalTemplateRels,
    HasSuspiciousMacroFunctionCalls,
    ViewedSuspiciousCalls,
    IsExcel,
    HasXlm4Macro,
    ViewedXlmSheets,
    HasHiddenSheets,
    ViewedHiddenSheets,
    IsPdf,
    PdfHasJavaScript,
    PdfHasOpenAction,
    ViewedPdfJs,
    ViewedPdfObjects,
    IsRtf,
    ContainsKnownExploitArtifacts,
    ViewedRtfControls,
    AbusesEquationEditor,
    IsPacked,
    HasOverlayData,
    ContainsIpLiteral,
    ContainsEmailAddress,
    ContainsSuspiciousKeywords,
    ContainsPersistenceArtifacts,
    ContainsEmbeddedScript,
    // Scripts
    IsScript,
    HasObfuscatedStrings,
    IsPowerShellScript,
    ContainsDownloaderCode,
    IsHTA,
    ContainsUrl,
    ViewedScriptSource,
    BeautifiedScript,
    ViewedEvalChains,
    // PE/ELF/Mach-O
    IsPe,
    HasHighEntropy,
    RanPackerId,
    ContainsEmbeddedExecutable,
    ViewedResources,
    ViewedImports,
    ViewedStrings,
    ViewedOverlay,
    IsSigned,
    SignatureValid,
    SignedByKnownVendor,
    ViewedSignature,
    ViewedSignatureProblems,
    SignatureTimestamped,
    // Archives / Installers / LNK
    IsArchive,
    ArchiveIsPasswordProtected,
    ExtractedArchiveSafely,
    ArchiveContainsExecutable,
    ViewedArchiveManifest,
    ArchiveDoubleExtensionMembers,
    ViewedDoubleExtensions,
    IsInstaller,
    MsiRunsCustomAction,
    ViewedMsiCustomActions,
    IsLnk,
    IsShortcutAbuseCandidate,
    ViewedLnkTarget,
    ContainsEmbeddedArchive,
    // Reputation / provenance
    MarkOfTheWeb,
    ViewedMOTW,
    HashInThreatIntel,
    ViewedThreatIntelHits,
    ComputedHashes,
    ViewedHashes,
    QueriedThreatIntel,
    ViewedOrigin,
    // Session / dynamic views
    Opened,
    OpenedSafely,
    LaunchedInSandbox,
    ViewedProcessTree,
    ViewedNetworkBehavior,
    ViewedFileSystemActivity,
    ViewedRegistryActivity,
    CapturedPcap,
    AppliedApiMonitors,
    // Runtime behaviors
    WritesToTempExecutable,
    DropsAndExecutes,
    CreatesRunKey,
    TriesToAccessTheInternet,
    BeaconingPattern,
    ResolvedDomains,
    UsesHTTPSRequests,
    UsesSelfSignedTls,
    ViewedTlsCertificates,
    PersistenceIndicatorsPresent,
    PersistenceReviewed,
    RequestsUacElevation,
    ViewedUacEvents,
    AcquiresSeDebugPrivilege,
    ViewedTokenPrivileges,
    MassFileModification,
    ViewedEncryptionMonitor,
    DeletesShadowCopies,
    ViewedShadowCopyEvents,
    DropsRansomNote,
    ViewedRansomNotes,
    ReadsManyDocs,
    ViewedExfilTimeline,
    CompressesBeforeUpload,
    UploadsLargeVolume,
    ChecksSandboxArtifacts,
    ViewedAntiVMChecks,
    DelaysExecutionLong,
    EnabledTimeWarp,
    UsesParentPidSpoofing,
    // Blob/string helpers
    ContainsBase64Blobs,
    DecodedBase64Blobs,
    ContainsHexBlobs,
    DecodedHexBlobs,
    ExtractedUrls,
    CarvedEmbeddedFiles,
    // Classifications
    IsSuspicious,
    IsMalicious,
    LikelyBenign,
    // Environment & safety
    InternetOriginCorroborated,
    SwitchedToIsolatedNetwork,
    CreatedSnapshot,
    // Reporting / outputs
    ExtractedIOCs,
    ExportedIOCs,
    GeneratedReport,

    //New:
    IsPCAP,
    HasNetworkConnections,
    HasConnectionWithExecutable,
    HasConnectionWithScript,
    // COUNT sentinel
    COUNT
};

enum class ActDefaultValues : ActId {
    // Office
    ViewMacros,
    DeobfuscateVBA,
    ViewExternalTemplates,
    ViewSuspiciousCalls,
    ViewXlmSheets,
    ViewHiddenSheets,
    // PDF/RTF
    ViewPdfJavaScript,
    ViewPdfObjects,
    ViewRtfControls,
    ViewOleObjects,
    // Script
    BeautifyScript,
    ViewDynamicEval,
    ViewScriptSource,
    // PE/ELF/Mach-O
    IdentifyPacker,
    ViewResources,
    ViewImports,
    ViewOverlay,
    ViewSignature,
    ViewSignatureProblems,
    // Archive/Installer/LNK
    ViewArchiveManifest,
    SafeExtract,
    ViewDoubleExtensions,
    ViewMsiCustomActions,
    ViewLnkTarget,
    // Reputation
    ViewMOTW,
    ViewThreatIntelHits,
    RecordPublisherTrust,
    ComputeHashes,
    QueryThreatIntel,
    ViewStrings,
    OpenStaticChecklist,
    // Dynamic
    LaunchSandbox,
    ViewProcessTree,
    ViewNetwork,
    ViewFileWrites,
    ViewRegistryChanges,
    StartCapturePcap,
    ViewDnsQueries,
    ViewTlsCertificates,
    // Persistence/Privilege
    ViewPersistence,
    ViewUac,
    ViewTokenPrivileges,
    // Ransomware/Exfil
    MonitorEncryption,
    ViewShadowCopyEvents,
    ViewRansomNotes,
    ViewExfil,
    // Safety
    OpenInSafeView,
    SwitchToIsolatedNetwork,
    CreateSnapshot,
    // IOC/Reports
    ExtractUrls,
    DecodeBase64,
    DecodeHex,
    CarveEmbedded,
    AddToCase,
    GenerateReport,
    ExportIOCs,
    // Anti-analysis helpers
    ViewAntiVM,
    EnableTimeWarp,
    // COUNT sentinel
    COUNT
};

// ---------------------- Name tables for enums ------------------------------ //
const std::vector<std::string> kPredNames = {
    // Must match enum Pred order exactly
    "IsWord",
    "HasMacros",
    "ViewedMacros",
    "HasMacroObfuscation",
    "DeobfuscatedVBA",
    "ContainsExternalTemplateRef",
    "ViewedExternalTemplateRels",
    "HasSuspiciousMacroFunctionCalls",
    "ViewedSuspiciousCalls",
    "IsExcel",
    "HasXlm4Macro",
    "ViewedXlmSheets",
    "HasHiddenSheets",
    "ViewedHiddenSheets",
    "IsPdf",
    "PdfHasJavaScript",
    "PdfHasOpenAction",
    "ViewedPdfJs",
    "ViewedPdfObjects",
    "IsRtf",
    "ContainsKnownExploitArtifacts",
    "ViewedRtfControls",
    "AbusesEquationEditor",
    "IsPacked",
    "HasOverlayData",
    "ContainsIpLiteral",
    "ContainsEmailAddress",
    "ContainsSuspiciousKeywords",
    "ContainsPersistenceArtifacts",
    "ContainsEmbeddedScript",
    // Scripts
    "IsScript",
    "HasObfuscatedStrings",
    "IsPowerShellScript",
    "ContainsDownloaderCode",
    "IsHTA",
    "ContainsUrl",
    "ViewedScriptSource",
    "BeautifiedScript",
    "ViewedEvalChains",
    // PE/ELF/Mach-O
    "IsPe",
    "HasHighEntropy",
    "RanPackerId",
    "ContainsEmbeddedExecutable",
    "ViewedResources",
    "ViewedImports",
    "ViewedOverlay",
    "ViewedStrings",
    "IsSigned",
    "SignatureValid",
    "SignedByKnownVendor",
    "ViewedSignature",
    "ViewedSignatureProblems",
    "SignatureTimestamped",
    // Archives / Installers / LNK
    "IsArchive",
    "ArchiveIsPasswordProtected",
    "ExtractedArchiveSafely",
    "ArchiveContainsExecutable",
    "ViewedArchiveManifest",
    "ArchiveDoubleExtensionMembers",
    "ViewedDoubleExtensions",
    "IsInstaller",
    "MsiRunsCustomAction",
    "ViewedMsiCustomActions",
    "IsLnk",
    "IsShortcutAbuseCandidate",
    "ViewedLnkTarget",
    "ContainsEmbeddedArchive",
    // Reputation / provenance
    "MarkOfTheWeb",
    "ViewedMOTW",
    "HashInThreatIntel",
    "ViewedThreatIntelHits",
    "ComputedHashes",
    "ViewedHashes",
    "QueriedThreatIntel",
    "ViewedOrigin",
    // Session / dynamic views
    "Opened",
    "OpenedSafely",
    "LaunchedInSandbox",
    "ViewedProcessTree",
    "ViewedNetworkBehavior",
    "ViewedFileSystemActivity",
    "ViewedRegistryActivity",
    "CapturedPcap",
    "AppliedApiMonitors",
    // Runtime behaviors
    "WritesToTempExecutable",
    "DropsAndExecutes",
    "CreatesRunKey",
    "TriesToAccessTheInternet",
    "BeaconingPattern",
    "ResolvedDomains",
    "UsesHTTPSRequests",
    "UsesSelfSignedTls",
    "ViewedTlsCertificates",
    "PersistenceIndicatorsPresent",
    "PersistenceReviewed",
    "RequestsUacElevation",
    "ViewedUacEvents",
    "AcquiresSeDebugPrivilege",
    "ViewedTokenPrivileges",
    "MassFileModification",
    "ViewedEncryptionMonitor",
    "DeletesShadowCopies",
    "ViewedShadowCopyEvents",
    "DropsRansomNote",
    "ViewedRansomNotes",
    "ReadsManyDocs",
    "ViewedExfilTimeline",
    "CompressesBeforeUpload",
    "UploadsLargeVolume",
    "ChecksSandboxArtifacts",
    "ViewedAntiVMChecks",
    "DelaysExecutionLong",
    "EnabledTimeWarp",
    "UsesParentPidSpoofing",
    // Blob/string helpers
    "ContainsBase64Blobs",
    "DecodedBase64Blobs",
    "ContainsHexBlobs",
    "DecodedHexBlobs",
    "ExtractedUrls",
    "CarvedEmbeddedFiles",
    // Classifications
    "IsSuspicious",
    "IsMalicious",
    "LikelyBenign",
    // Environment & safety
    "InternetOriginCorroborated",
    "SwitchedToIsolatedNetwork",
    "CreatedSnapshot",
    // Reporting / outputs
    "ExtractedIOCs",
    "ExportedIOCs",
    "GeneratedReport",

    // New:
    "IsPCAP",
    "HasNetworkConnections",
    "HasConnectionWithExecutable",
    "HasConnectionWithScript",
};

const std::vector<std::string> kActNames = {
    // Office
    "ViewMacros",
    "DeobfuscateVBA",
    "ViewExternalTemplates",
    "ViewSuspiciousCalls",
    "ViewXlmSheets",
    "ViewHiddenSheets",
    // PDF/RTF
    "ViewPdfJavaScript",
    "ViewPdfObjects",
    "ViewRtfControls",
    "ViewOleObjects",
    // Script
    "BeautifyScript",
    "ViewDynamicEval",
    "ViewScriptSource",
    // PE/ELF/Mach-O
    "IdentifyPacker",
    "ViewResources",
    "ViewImports",
    "ViewOverlay",
    "ViewSignature",
    "ViewSignatureProblems",
    // Archive/Installer/LNK
    "ViewArchiveManifest",
    "SafeExtract",
    "ViewDoubleExtensions",
    "ViewMsiCustomActions",
    "ViewLnkTarget",
    // Reputation
    "ViewMOTW",
    "ViewThreatIntelHits",
    "RecordPublisherTrust",
    "ComputeHashes",
    "QueryThreatIntel",
    "ViewStrings",
    "OpenStaticChecklist",
    // Dynamic
    "LaunchSandbox",
    "ViewProcessTree",
    "ViewNetwork",
    "ViewFileWrites",
    "ViewRegistryChanges",
    "StartCapturePcap",
    "ViewDnsQueries",
    "ViewTlsCertificates",
    // Persistence/Privilege
    "ViewPersistence",
    "ViewUac",
    "ViewTokenPrivileges",
    // Ransomware/Exfil
    "MonitorEncryption",
    "ViewShadowCopyEvents",
    "ViewRansomNotes",
    "ViewExfil",
    // Safety
    "OpenInSafeView",
    "SwitchToIsolatedNetwork",
    "CreateSnapshot",
    // IOC/Reports
    "ExtractUrls",
    "DecodeBase64",
    "DecodeHex",
    "CarveEmbedded",
    "AddToCase",
    "GenerateReport",
    "ExportIOCs",
    // Anti-analysis helpers
    "ViewAntiVM",
    "EnableTimeWarp"
};

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

RuleEngine::RuleEngine() : impl_(std::make_unique<Impl>())
{
}
RuleEngine::~RuleEngine() noexcept = default;

bool RuleEngine::Init()
{
    auto status = install_builtin_rules();
    // TODO: show the error message somewhere
    return status.ok;
}

bool RuleEngine::SubmitFact(const Fact& fact)
{
    return set_fact(fact).ok;
}

ActId RuleEngine::GetActId(std::string_view name) const
{
    auto it = std::find(kActNames.begin(), kActNames.end(), name);
    if (it == kActNames.end())
        return INVALID_ACT_ID;
    return static_cast<ActId>(std::distance(kActNames.begin(), it));
}

PredId RuleEngine::GetPredId(std::string_view name) const
{
    auto it = std::find(kPredNames.begin(), kPredNames.end(), name);
    if (it == kPredNames.end())
        return INVALID_PRED_ID;
    return static_cast<PredId>(std::distance(kPredNames.begin(), it));
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
                    sug.action       = r.action;
                    sug.severity     = r.severity;
                    sug.message      = r.message;
                    sug.cooldown     = r.cooldown;
                    sug.last_emitted = now();
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
        auto R =
              [&](std::string id, ConjClause c, ActDefaultValues ak, Severity sev, std::string msg, std::chrono::milliseconds cd = std::chrono::minutes(30)) {
                  Rule r;
                  r.id       = std::move(id);
                  r.clause   = std::move(c);
                  r.action   = { (ActId) ak, Subject{} };
                  r.severity = sev;
                  r.message  = std::move(msg);
                  r.cooldown = cd;
                  return register_rule(r);
              };
        auto C = [&](std::initializer_list<Literal> lits, int win_ms = 0) { return clause(lits, std::chrono::milliseconds{ win_ms }); };

        // File-only
        R("F-001",
          C({ lit(PredDefaultValues::IsWord), lit(PredDefaultValues::HasMacros) }),
          ActDefaultValues::ViewMacros,
          Severity::High,
          "Macros present. Open Macro Viewer?");
        R("F-002",
          C({ lit(PredDefaultValues::IsWord), lit(PredDefaultValues::HasMacroObfuscation) }),
          ActDefaultValues::DeobfuscateVBA,
          Severity::High,
          "Obfuscated macros detected. Deobfuscate now?");
        R("F-003",
          C({ lit(PredDefaultValues::IsWord), lit(PredDefaultValues::ContainsExternalTemplateRef) }),
          ActDefaultValues::ViewExternalTemplates,
          Severity::Warn,
          "External template reference. Inspect RELs?");
        R("F-004",
          C({ lit(PredDefaultValues::IsExcel), lit(PredDefaultValues::HasXlm4Macro) }),
          ActDefaultValues::ViewXlmSheets,
          Severity::High,
          "Excel 4.0 macro sheet present. Review?");
        R("F-005",
          C({ lit(PredDefaultValues::IsExcel), lit(PredDefaultValues::HasHiddenSheets) }),
          ActDefaultValues::ViewHiddenSheets,
          Severity::Warn,
          "Hidden sheets found. Show list?");
        R("F-010",
          C({ lit(PredDefaultValues::IsPdf), lit(PredDefaultValues::PdfHasJavaScript) }),
          ActDefaultValues::ViewPdfJavaScript,
          Severity::High,
          "PDF has JavaScript. Inspect code?");
        R("F-011",
          C({ lit(PredDefaultValues::IsPdf), lit(PredDefaultValues::PdfHasOpenAction) }),
          ActDefaultValues::ViewPdfObjects,
          Severity::High,
          "Auto-action triggers on open. Inspect objects?");
        R("F-020",
          C({ lit(PredDefaultValues::IsScript), lit(PredDefaultValues::HasObfuscatedStrings) }),
          ActDefaultValues::BeautifyScript,
          Severity::High,
          "Obfuscated script. Beautify for review?");
        R("F-030",
          C({ lit(PredDefaultValues::IsPe), lit(PredDefaultValues::HasHighEntropy) }),
          ActDefaultValues::IdentifyPacker,
          Severity::Warn,
          "High entropy suggests packing. Identify packer?");
        R("F-031",
          C({ lit(PredDefaultValues::IsPe), lit(PredDefaultValues::ContainsEmbeddedExecutable) }),
          ActDefaultValues::ViewResources,
          Severity::Warn,
          "Embedded payload(s) detected. Inspect resources?");
        R("F-040",
          C({ lit(PredDefaultValues::IsArchive), lit(PredDefaultValues::ArchiveIsPasswordProtected) }),
          ActDefaultValues::SafeExtract,
          Severity::Warn,
          "Password-protected archive. Safe-extract to sandbox?");
        R("F-041",
          C({ lit(PredDefaultValues::IsArchive), lit(PredDefaultValues::ArchiveContainsExecutable) }),
          ActDefaultValues::ViewArchiveManifest,
          Severity::Warn,
          "Executable(s) inside archive. Review manifest?");
        R("F-050",
          C({ lit(PredDefaultValues::MarkOfTheWeb) }),
          ActDefaultValues::ViewMOTW,
          Severity::Info,
          "Internet-origin marker present. Inspect source zone?");
        R("F-051",
          C({ lit(PredDefaultValues::HashInThreatIntel) }),
          ActDefaultValues::ViewThreatIntelHits,
          Severity::Critical,
          "Known-bad hash in intel. Review details now.",
          std::chrono::minutes(5));

        // User-only
        R("U-100",
          C({ lit(PredDefaultValues::Opened), lit(PredDefaultValues::ViewedHashes, true) }),
          ActDefaultValues::ComputeHashes,
          Severity::Info,
          "Compute hashes for correlation & TI lookups?");
        R("U-101",
          C({ lit(PredDefaultValues::ComputedHashes), lit(PredDefaultValues::QueriedThreatIntel, true) }),
          ActDefaultValues::QueryThreatIntel,
          Severity::Info,
          "Check reputation across intel sources?");
        R("U-102",
          C({ lit(PredDefaultValues::Opened), lit(PredDefaultValues::ViewedStrings, true) }),
          ActDefaultValues::ViewStrings,
          Severity::Info,
          "Review strings for URLs and IOCs?");
        R("U-120",
          C({ lit(PredDefaultValues::Opened), lit(PredDefaultValues::OpenedSafely, true), lit(PredDefaultValues::IsWord) }),
          ActDefaultValues::OpenInSafeView,
          Severity::High,
          "Use protected view to avoid executing active content.");
        R("U-121",
          C({ lit(PredDefaultValues::Opened), lit(PredDefaultValues::SwitchedToIsolatedNetwork, true), lit(PredDefaultValues::MarkOfTheWeb) }),
          ActDefaultValues::SwitchToIsolatedNetwork,
          Severity::High,
          "Switch to isolated/no-Internet sandbox.");
        R("U-122",
          C({ lit(PredDefaultValues::Opened), lit(PredDefaultValues::CreatedSnapshot, true) }),
          ActDefaultValues::CreateSnapshot,
          Severity::Info,
          "Create VM snapshot before detonation?");

        // Mixed (subset of comprehensive rulebook)
        R("M-200",
          C({ lit(PredDefaultValues::IsWord), lit(PredDefaultValues::HasMacros), lit(PredDefaultValues::ViewedMacros, true) }),
          ActDefaultValues::ViewMacros,
          Severity::High,
          "Macros present. Open Macro Viewer?");
        R("M-201",
          C({ lit(PredDefaultValues::HasMacroObfuscation), lit(PredDefaultValues::DeobfuscatedVBA, true) }),
          ActDefaultValues::DeobfuscateVBA,
          Severity::High,
          "Obfuscated macros found. Deobfuscate now?");
        R("M-202",
          C({ lit(PredDefaultValues::HasSuspiciousMacroFunctionCalls), lit(PredDefaultValues::ViewedSuspiciousCalls, true) }),
          ActDefaultValues::ViewSuspiciousCalls,
          Severity::High,
          "Suspicious macro APIs detected. Review call list?");
        R("M-203",
          C({ lit(PredDefaultValues::ContainsExternalTemplateRef), lit(PredDefaultValues::ViewedExternalTemplateRels, true) }),
          ActDefaultValues::ViewExternalTemplates,
          Severity::Warn,
          "Remote template reference. Inspect RELs?");

        R("M-210",
          C({ lit(PredDefaultValues::ContainsBase64Blobs), lit(PredDefaultValues::DecodedBase64Blobs, true) }),
          ActDefaultValues::DecodeBase64,
          Severity::Warn,
          "Base64 blobs detected. Decode for payloads?");
        R("M-211",
          C({ lit(PredDefaultValues::ContainsHexBlobs), lit(PredDefaultValues::DecodedHexBlobs, true) }),
          ActDefaultValues::DecodeHex,
          Severity::Info,
          "Hex blobs present. Decode now?");
        R("M-212",
          C({ lit(PredDefaultValues::ContainsUrl), lit(PredDefaultValues::ExtractedUrls, true) }),
          ActDefaultValues::ExtractUrls,
          Severity::Info,
          "Extract URLs for pivoting & blocking?");
        R("M-213",
          C({ lit(PredDefaultValues::ContainsEmbeddedArchive), lit(PredDefaultValues::CarvedEmbeddedFiles, true) }),
          ActDefaultValues::CarveEmbedded,
          Severity::Warn,
          "Embedded archive(s) found. Carve safely?");

        R("M-220",
          C({ lit(PredDefaultValues::IsPe), lit(PredDefaultValues::ViewedImports, true) }),
          ActDefaultValues::ViewImports,
          Severity::Info,
          "Review imported APIs for intent?");
        R("M-221",
          C({ lit(PredDefaultValues::IsPe), lit(PredDefaultValues::HasHighEntropy), lit(PredDefaultValues::RanPackerId, true) }),
          ActDefaultValues::IdentifyPacker,
          Severity::Warn,
          "Likely packed. Identify packer?");
        R("M-223",
          C({ lit(PredDefaultValues::IsPe), lit(PredDefaultValues::ViewedOverlay, true) }),
          ActDefaultValues::ViewOverlay,
          Severity::Info,
          "Overlay data present. Inspect trailing bytes?");

        R("M-230",
          C({ lit(PredDefaultValues::TriesToAccessTheInternet), lit(PredDefaultValues::ViewedNetworkBehavior, true) }),
          ActDefaultValues::ViewNetwork,
          Severity::High,
          "Outbound connections observed. Review endpoints?");
        R("M-231",
          C({ lit(PredDefaultValues::BeaconingPattern), lit(PredDefaultValues::ResolvedDomains, true) }),
          ActDefaultValues::ViewDnsQueries,
          Severity::High,
          "Beaconing detected. Review DNS queries/domains?");
        R("M-232",
          C({ lit(PredDefaultValues::UsesHTTPSRequests), lit(PredDefaultValues::UsesSelfSignedTls), lit(PredDefaultValues::ViewedTlsCertificates, true) }),
          ActDefaultValues::ViewTlsCertificates,
          Severity::High,
          "Self-signed/invalid TLS. Inspect certificate chain?");
        R("M-233",
          C({ lit(PredDefaultValues::WritesToTempExecutable), lit(PredDefaultValues::ViewedFileSystemActivity, true) }),
          ActDefaultValues::ViewFileWrites,
          Severity::High,
          "New executable(s) in temp. Review drops?");
        R("M-234",
          C({ lit(PredDefaultValues::DropsAndExecutes), lit(PredDefaultValues::ViewedProcessTree, true) }),
          ActDefaultValues::ViewProcessTree,
          Severity::High,
          "Drop-and-run sequence observed. Open process tree?");
        R("M-235",
          C({ lit(PredDefaultValues::CreatesRunKey), lit(PredDefaultValues::ViewedRegistryActivity, true) }),
          ActDefaultValues::ViewRegistryChanges,
          Severity::High,
          "Startup persistence detected. Inspect registry changes?");

        R("M-240",
          C({ lit(PredDefaultValues::PersistenceIndicatorsPresent), lit(PredDefaultValues::PersistenceReviewed, true) }),
          ActDefaultValues::ViewPersistence,
          Severity::High,
          "Persistence artifacts found. Review them now?");
        R("M-241",
          C({ lit(PredDefaultValues::RequestsUacElevation), lit(PredDefaultValues::ViewedUacEvents, true) }),
          ActDefaultValues::ViewUac,
          Severity::Warn,
          "UAC prompt/elevation attempt. Inspect event details?");
        R("M-242",
          C({ lit(PredDefaultValues::AcquiresSeDebugPrivilege), lit(PredDefaultValues::ViewedTokenPrivileges, true) }),
          ActDefaultValues::ViewTokenPrivileges,
          Severity::High,
          "Debug privilege acquired. Review token changes?");

        R("M-250",
          C({ lit(PredDefaultValues::MassFileModification), lit(PredDefaultValues::ViewedEncryptionMonitor, true) }),
          ActDefaultValues::MonitorEncryption,
          Severity::Critical,
          "Rapid file modifications. Start encryption monitor?");
        R("M-251",
          C({ lit(PredDefaultValues::DeletesShadowCopies), lit(PredDefaultValues::ViewedShadowCopyEvents, true) }),
          ActDefaultValues::ViewShadowCopyEvents,
          Severity::High,
          "VSS deletion observed. Inspect events?");
        R("M-252",
          C({ lit(PredDefaultValues::DropsRansomNote), lit(PredDefaultValues::ViewedRansomNotes, true) }),
          ActDefaultValues::ViewRansomNotes,
          Severity::High,
          "Ransom note artifacts dropped. Open list?");

        R("M-260",
          C({ lit(PredDefaultValues::ReadsManyDocs), lit(PredDefaultValues::ViewedExfilTimeline, true) }),
          ActDefaultValues::ViewExfil,
          Severity::High,
          "Mass document reads. Check exfil timeline?");
        R("M-262",
          C({ lit(PredDefaultValues::UploadsLargeVolume), lit(PredDefaultValues::CapturedPcap, true) }),
          ActDefaultValues::StartCapturePcap,
          Severity::High,
          "Large outbound traffic. Capture PCAP now?");

        R("M-270",
          C({ lit(PredDefaultValues::ChecksSandboxArtifacts), lit(PredDefaultValues::ViewedAntiVMChecks, true) }),
          ActDefaultValues::ViewAntiVM,
          Severity::Warn,
          "Anti-VM checks observed. Review heuristics?");
        R("M-271",
          C({ lit(PredDefaultValues::DelaysExecutionLong), lit(PredDefaultValues::EnabledTimeWarp, true) }),
          ActDefaultValues::EnableTimeWarp,
          Severity::Info,
          "Long sleeps observed. Enable time warp?");

        R("M-280",
          C({ lit(PredDefaultValues::IsArchive), lit(PredDefaultValues::ArchiveIsPasswordProtected), lit(PredDefaultValues::ExtractedArchiveSafely, true) }),
          ActDefaultValues::SafeExtract,
          Severity::Warn,
          "Password-protected archive. Extract to sandbox?");
        R("M-290",
          C({ lit(PredDefaultValues::ComputedHashes), lit(PredDefaultValues::QueriedThreatIntel, true), lit(PredDefaultValues::ContainsUrl) }),
          ActDefaultValues::QueryThreatIntel,
          Severity::Info,
          "Reputation check likely useful here. Query TI?");
        R("M-292",
          C({ lit(PredDefaultValues::IsSuspicious), lit(PredDefaultValues::ExtractedUrls, true) }),
          ActDefaultValues::ExtractUrls,
          Severity::High,
          "Extract IOCs to pivot and contain?");
        R("M-293",
          C({ lit(PredDefaultValues::IsSuspicious), lit(PredDefaultValues::ExportedIOCs, true) }),
          ActDefaultValues::ExportIOCs,
          Severity::Info,
          "Export IOCs (CSV/STIX) for sharing?");
        R("M-294",
          C({ lit(PredDefaultValues::IsMalicious), lit(PredDefaultValues::GeneratedReport, true) }),
          ActDefaultValues::GenerateReport,
          Severity::High,
          "Generate a concise report with findings?");

        // Time-windowed examples
        R("P-301",
          C({ lit(PredDefaultValues::WritesToTempExecutable), lit(PredDefaultValues::DropsAndExecutes) }, 180000),
          ActDefaultValues::ViewProcessTree,
          Severity::High,
          "Drop-and-run chain just occurred. Open process graph.");
        R("P-302",
          C({ lit(PredDefaultValues::TriesToAccessTheInternet) }, 600000),
          ActDefaultValues::ViewNetwork,
          Severity::High,
          "Recent network activity. Review flows.");
        R("P-303",
          C({ lit(PredDefaultValues::CreatesRunKey) }, 600000),
          ActDefaultValues::ViewPersistence,
          Severity::High,
          "New persistence. Review startup artifacts.");

        return Status::OK();
    } catch (const std::exception& e) {
        const auto err = std::format("install_builtin_rules: {}", e.what());
        return Status::Error(err);
    } catch (...) {
        return Status::Error("install_builtin_rules: unknown");
    }
}

} // namespace GView::Components::AnalysisEngine
