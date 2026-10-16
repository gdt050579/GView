// Unit tests of the HDF vocabulary tooling: module declarations (CollectingRegistry / RuntimeRegistry), the inference of
// derived predicates, "hdf augment" (merge rules, --dry-run, --check) and "hdf validate" (drift error classes).

#include "Tooling.hpp"

#include <catch.hpp>

#include <fstream>
#include <random>
#include <sstream>

using namespace GView::HDF;
using namespace GView::HDF::Tooling;
using nlohmann::ordered_json;

namespace
{
using DeclareFn = std::function<void(VocabularyBuilderInterface&)>;

// modules without libraries: Core:HDF plus the given fake plugins
class FakeCollector : public VocabularyCollector
{
  public:
    std::vector<std::pair<std::string, DeclareFn>> modules;
    std::vector<ModuleDeclarations> CollectAll(const std::function<bool(std::string_view)>& knownSort, std::vector<std::string>&) override
    {
        std::vector<ModuleDeclarations> result;
        CollectingRegistry core("Core:HDF", knownSort);
        DeclareBuiltins(core.HDFVocabulary());
        result.push_back(core.TakeDeclarations());
        for (const auto& [generator, declare] : modules) {
            CollectingRegistry registry(generator, knownSort);
            declare(registry.HDFVocabulary());
            result.push_back(registry.TakeDeclarations());
        }
        return result;
    }
};

FakeCollector MakeCollector()
{
    FakeCollector c;
    c.modules.push_back({ "Plugin:PE", [](VocabularyBuilderInterface& v) {
                             v.Predicate("IsPE", { { "x", "Subject" } }, "{x} is a PE file");
                             v.Predicate("HasImport", { { "x", "Subject" }, { "api", "String" } }, "{x} imports {api}");
                             v.Predicate("HasSection", { { "x", "Subject" }, { "name", "String" }, { "size", "Int" } }, "{x} has section {name}");
                         } });
    c.modules.push_back({ "Plugin:PCAP", [](VocabularyBuilderInterface& v) {
                             v.Predicate("IsPCAP", { { "x", "Subject" } }, "{x} is a capture");
                             v.Action("CheckConnections", { { "x", "Subject" } }, "Identify the connections in {x}");
                         } });
    c.modules.push_back({ "Plugin:ELF", [](VocabularyBuilderInterface& v) {
                             v.Predicate("HasSection", { { "x", "Subject" }, { "name", "String" }, { "size", "Int" } }, "{x} has section {name}");
                         } });
    return c;
}

// the hand-written part of a specification (MSVC: raw strings stay outside macro arguments)
const std::string HAND_WRITTEN = R"J({
  "description": "test specification",
  "sorts": [ { "name": "Domain", "kind": "String" } ],
  "predicates": [
    { "name": "HasMaliciousness", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "score", "sort": "Real" } ], "denotation": "{x} scores {score}", "generator": [ "Manual" ] },
    { "name": "Orphan", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "gone", "generator": [ "Plugin:Removed" ] },
    { "name": "HandWritten", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "kept as is" }
  ],
  "verdicts": [ "HasMaliciousness" ],
  "assertion_rules": [
    { "name": "Injection", "body": [ "IsPE(x)", "HasImport(x, \"VirtualAlloc\")" ], "head": "IndicatesInjection(x)" },
    { "name": "Score", "body": [ "IndicatesInjection(x)" ], "head": "HasMaliciousness(x, 0.80)" },
    { "name": "Typed", "body": [ "HasSection(x, n, s)" ], "head": "SectionInfo(x, n, s, 3, \"tag\", true, 2.5)" }
  ],
  "action_rules": [ { "name": "Connections", "body": [ "IsPCAP(x)" ], "head": "CheckConnections(x)" } ],
  "interpretation": { "outcomes": [ "Malicious" ],
                      "labels": [ { "outcome": "Malicious", "propagate": true, "clauses": [ { "present": "HasMaliciousness", "op": ">=", "value": 0.7 } ] } ] },
  "stopping": { "policy": "conclusive", "max_steps": 0 }
})J";

ordered_json Parse(const std::string& text)
{
    auto doc = ordered_json::parse(text, nullptr, false);
    REQUIRE_FALSE(doc.is_discarded());
    return doc;
}

const ordered_json* FindEntry(const ordered_json& doc, const char* section, std::string_view name)
{
    for (const auto& e : doc[section])
        if (e["name"] == std::string(name))
            return &e;
    return nullptr;
}

std::vector<ModuleDeclarations> Modules(FakeCollector& c, const ordered_json& doc)
{
    std::vector<std::string> warnings;
    return c.CollectAll(
          [&doc](std::string_view s) {
              for (const auto& e : doc["sorts"])
                  if (e["name"] == std::string(s))
                      return true;
              return false;
          },
          warnings);
}

struct TempFolder {
    std::filesystem::path path;
    TempFolder()
    {
        std::random_device rd;
        path = std::filesystem::temp_directory_path() / ("gview_hdf_tooling_" + std::to_string(rd()));
        std::filesystem::create_directories(path);
    }
    ~TempFolder()
    {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

std::string ReadFile(const std::filesystem::path& p)
{
    std::ifstream f(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}
void WriteFile(const std::filesystem::path& p, const std::string& text)
{
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << text;
}
} // namespace

TEST_CASE("hdf: tooling collecting registry", "[hdf][tooling]")
{
    CollectingRegistry r("Plugin:X", [](std::string_view s) { return s == "Domain"; });
    auto& v = r.HDFVocabulary();
    REQUIRE(v.Predicate("P", { { "x", "Subject" }, { "d", "Domain" } }, "{x} {d}"));
    REQUIRE_FALSE(v.Predicate("P", { { "x", "Subject" } }, "")); // duplicate within the module
    REQUIRE_FALSE(v.Predicate("Q", { { "x", "Nope" } }, ""));    // unknown sort
    REQUIRE_FALSE(v.Predicate("Bad Name", { { "x", "Subject" } }, ""));
    REQUIRE_FALSE(v.Action(
          "A",
          { { "a", "Int" }, { "b", "Int" }, { "c", "Int" }, { "d", "Int" }, { "e", "Int" }, { "f", "Int" }, { "g", "Int" }, { "h", "Int" }, { "i", "Int" } },
          ""));
    REQUIRE(v.Sort("Hash", "String"));
    REQUIRE(v.Sort("Hash", "String")); // first declaration wins
    REQUIRE_FALSE(v.Sort("Hash", "Int"));
    REQUIRE(v.Predicate("HasHash", { { "x", "Subject" }, { "h", "Hash" } }, "")); // a sort declared by the module itself
    REQUIRE(v.Action("Scan", { { "x", "Subject" } }, "Scan {x}", true));
    const auto& d = r.Declarations();
    REQUIRE(d.predicates.size() == 2);
    REQUIRE(d.actions.size() == 1);
    REQUIRE(d.actions[0].repeatable);
    REQUIRE(d.errors.size() == 5);
}

TEST_CASE("hdf: tooling runtime registry drift check", "[hdf][tooling]")
{
    Diagnostics diag;
    const std::string json = R"J({ "predicates": [ { "name": "IsPE", "arity": [ { "name": "x", "sort": "Subject" } ] } ],
                                   "actions": [ { "name": "Check", "arity": [ { "name": "x", "sort": "Subject" } ] } ] })J";
    auto spec              = LoadSpecificationText(json, diag);
    REQUIRE(spec);
    std::vector<uint8> rejectedPredicates, rejectedActions;
    RuntimeRegistry r("Plugin:PE", spec->signature);
    r.HDFVocabulary().Predicate("IsPE", { { "x", "Subject" } }, "{x} is a PE file");           // matches
    r.HDFVocabulary().Predicate("NewFact", { { "x", "Subject" }, { "n", "Int" } }, "{x} {n}"); // unknown: appended
    r.HDFVocabulary().Action("Check", { { "x", "Subject" }, { "y", "Subject" } }, "mismatch"); // arity mismatch
    const auto report = r.Apply(*spec, rejectedPredicates, rejectedActions);
    REQUIRE(report.appended.size() == 1);
    REQUIRE(report.rejected.size() == 1);
    const auto newFact = spec->signature.predicates.Find("NewFact");
    REQUIRE(newFact != INVALID_PREDICATE_ID);
    REQUIRE(spec->signature.generators.Name(spec->signature.predicates.Get(newFact).generators.at(0)) == "Plugin:PE");
    const auto check = spec->signature.actions.Find("Check");
    REQUIRE(check < rejectedActions.size());
    REQUIRE(rejectedActions[check] == 1);
    // the matching predicate gets the module as a generator
    const auto isPE = spec->signature.predicates.Find("IsPE");
    REQUIRE(spec->signature.predicates.Get(isPE).generators.size() == 1);
}

TEST_CASE("hdf: tooling inference of derived predicates", "[hdf][tooling]")
{
    auto collector  = MakeCollector();
    const auto doc  = Parse(HAND_WRITTEN);
    const auto mods = Modules(collector, doc);
    Diagnostics d;
    const auto derived = InferDerivedPredicates(doc, mods, d);
    INFO(d.ToText());
    REQUIRE_FALSE(d.HasErrors());
    REQUIRE(derived.size() == 3);
    REQUIRE(derived[0].generator == "Rule:Injection");
    REQUIRE(derived[0].predicates[0].name == "IndicatesInjection");
    REQUIRE(derived[0].predicates[0].arity == std::vector<DeclaredArgument>{ { "x", "Subject" } });
    REQUIRE(derived[0].predicates[0].denotation == "IndicatesInjection({x})");
    // a derived predicate used by another rule: Score's head is a Real constant
    REQUIRE(derived[1].predicates[0].arity == std::vector<DeclaredArgument>{ { "x", "Subject" }, { "arg2", "Real" } });
    // Int vs Real vs String vs Bool constants, sorts of variables from the body
    const std::vector<DeclaredArgument> typed = { { "x", "Subject" },   { "n", "String" },  { "s", "Int" },    { "arg4", "Int" },
                                                  { "arg5", "String" }, { "arg6", "Bool" }, { "arg7", "Real" } };
    REQUIRE(derived[2].predicates[0].arity == typed);

    // two rules with the same head and different inferred arities are an error
    auto inconsistent = doc;
    inconsistent["assertion_rules"].push_back(ordered_json{ { "name", "Other" }, { "body", { "IsPE(x)" } }, { "head", "IndicatesInjection(x, 1)" } });
    Diagnostics d2;
    InferDerivedPredicates(inconsistent, mods, d2);
    REQUIRE(d2.Contains("another arity", Diagnostic::Severity::Error));
    AugmentResult result;
    Diagnostics d3;
    REQUIRE_FALSE(Augment(inconsistent, mods, result, d3));
}

TEST_CASE("hdf: tooling augment merge rules", "[hdf][tooling]")
{
    auto collector  = MakeCollector();
    const auto doc  = Parse(HAND_WRITTEN);
    const auto mods = Modules(collector, doc);
    AugmentResult result;
    Diagnostics d;
    REQUIRE(Augment(doc, mods, result, d));
    INFO(d.ToText());
    const auto& out = result.document;
    // the hand-written sections keep their key order (ordered_json round trip)
    std::vector<std::string> keys;
    for (auto it = out.begin(); it != out.end(); ++it)
        keys.push_back(it.key());
    REQUIRE(
          keys == std::vector<std::string>{
                        "description", "sorts", "predicates", "verdicts", "assertion_rules", "action_rules", "interpretation", "stopping", "actions" });
    std::vector<std::string> ruleKeys;
    for (auto it = out["assertion_rules"][0].begin(); it != out["assertion_rules"][0].end(); ++it)
        ruleKeys.push_back(it.key());
    REQUIRE(ruleKeys == std::vector<std::string>{ "name", "body", "head" });
    // Manual: kept verbatim, the rule that derives it is added to its generators
    const auto* mal = FindEntry(out, "predicates", "HasMaliciousness");
    REQUIRE(mal);
    REQUIRE((*mal)["denotation"] == "{x} scores {score}");
    REQUIRE((*mal)["generator"] == ordered_json::array({ "Manual", "Rule:Score" }));
    // no generator key => Manual
    const auto* hand = FindEntry(out, "predicates", "HandWritten");
    REQUIRE(hand);
    REQUIRE((*hand)["generator"] == ordered_json::array({ "Manual" }));
    // orphans (module generators only, declared by nobody) are removed
    REQUIRE_FALSE(FindEntry(out, "predicates", "Orphan"));
    REQUIRE(std::find(result.removed.begin(), result.removed.end(), "predicates Orphan") != result.removed.end());
    // module entries: union of the declaring modules, sorted
    const auto* section = FindEntry(out, "predicates", "HasSection");
    REQUIRE(section);
    REQUIRE((*section)["generator"] == ordered_json::array({ "Plugin:ELF", "Plugin:PE" }));
    // built-ins, derived predicates and completion predicates are generated
    REQUIRE(FindEntry(out, "predicates", "ExtractedFrom"));
    REQUIRE((*FindEntry(out, "predicates", "IndicatesInjection"))["generator"] == ordered_json::array({ "Rule:Injection" }));
    const auto* done = FindEntry(out, "predicates", "Done_CheckConnections");
    REQUIRE(done);
    REQUIRE((*done)["generator"] == ordered_json::array({ "Core:HDF" }));
    REQUIRE(FindEntry(out, "actions", "ReanalyzeSelection"));
    REQUIRE((*FindEntry(out, "actions", "CheckConnections"))["repeatable"] == false);
    // the result validates and a second augment is a fixpoint
    Diagnostics v;
    Validate(out, mods, v);
    INFO(v.ToText());
    REQUIRE_FALSE(v.HasErrors());
    AugmentResult again;
    Diagnostics d2;
    REQUIRE(Augment(out, mods, again, d2));
    REQUIRE(Serialize(again.document) == Serialize(out));
    REQUIRE(again.added.empty());
    REQUIRE(again.updated.empty());
    REQUIRE(again.removed.empty());
    // a module entry is rewritten when the module changes its declaration
    auto changed = out;
    for (auto& e : changed["predicates"])
        if (e["name"] == "IsPE")
            e["denotation"] = "stale";
    AugmentResult rewritten;
    Diagnostics d3;
    REQUIRE(Augment(changed, mods, rewritten, d3));
    REQUIRE((*FindEntry(rewritten.document, "predicates", "IsPE"))["denotation"] == "{x} is a PE file");
}

TEST_CASE("hdf: tooling validate drift classes", "[hdf][tooling]")
{
    auto collector  = MakeCollector();
    const auto mods = Modules(collector, Parse(HAND_WRITTEN));
    AugmentResult result;
    Diagnostics d;
    REQUIRE(Augment(Parse(HAND_WRITTEN), mods, result, d));
    const auto good = result.document;
    using S         = Diagnostic::Severity;

    // declared by a module but missing from the file
    auto missing = good;
    auto& preds  = missing["predicates"];
    for (size_t i = 0; i < preds.size(); i++)
        if (preds[i]["name"] == "IsPE") {
            preds.erase(i);
            break;
        }
    Diagnostics d1;
    Validate(missing, mods, d1);
    REQUIRE(d1.Contains("declared by Plugin:PE but missing", S::Error));
    // the module declares another arity
    auto mismatch = good;
    for (auto& e : mismatch["predicates"])
        if (e["name"] == "HasImport")
            e["arity"][1]["sort"] = "Int";
    Diagnostics d2;
    Validate(mismatch, mods, d2);
    REQUIRE(d2.Contains("Plugin:PE declares HasImport", S::Error));
    // a generator that no longer declares the symbol
    auto stale = good;
    for (auto& e : stale["predicates"])
        if (e["name"] == "IsPCAP")
            e["generator"] = ordered_json::array({ "Plugin:PCAP", "Plugin:Gone" });
    Diagnostics d3;
    Validate(stale, mods, d3);
    REQUIRE(d3.Contains("Plugin:Gone no longer declares", S::Error));
    // a stale Rule: generator (the rule was removed)
    auto staleRule = good;
    for (auto& e : staleRule["predicates"])
        if (e["name"] == "IndicatesInjection")
            e["generator"] = ordered_json::array({ "Rule:Injection", "Rule:Deleted" });
    Diagnostics d4;
    Validate(staleRule, mods, d4);
    REQUIRE(d4.Contains("the rule Deleted no longer exists", S::Error));
    // the inferred arity differs from the file
    auto inferred = good;
    for (auto& e : inferred["predicates"])
        if (e["name"] == "IndicatesInjection")
            e["arity"][0]["sort"] = "String";
    Diagnostics d5;
    Validate(inferred, mods, d5);
    REQUIRE(d5.Contains("inferred from Rule:Injection", S::Error));
    // a missing generator list
    auto noGenerator = good;
    noGenerator["actions"][0].erase("generator");
    Diagnostics d6;
    Validate(noGenerator, mods, d6);
    REQUIRE(d6.Contains("generator", S::Error));
    // an unused Manual predicate is a warning; an action only Manual can produce is a warning
    auto bogus = good;
    bogus["predicates"].push_back(
          ordered_json{ { "name", "Bogus" }, { "arity", ordered_json::array() }, { "denotation", "bogus" }, { "generator", { "Manual" } } });
    bogus["actions"].push_back(ordered_json{
          { "name", "Dream" }, { "arity", ordered_json::array() }, { "denotation", "dream" }, { "repeatable", true }, { "generator", { "Manual" } } });
    Diagnostics d7;
    Validate(bogus, mods, d7);
    REQUIRE_FALSE(d7.HasErrors());
    REQUIRE(d7.Contains("Bogus is referenced by no rule", S::Warning));
    REQUIRE(d7.Contains("action Dream has no generator", S::Warning));
    // the generator list differs from the declaring modules (warning)
    auto partial = good;
    for (auto& e : partial["predicates"])
        if (e["name"] == "HasSection")
            e["generator"] = ordered_json::array({ "Plugin:PE" });
    Diagnostics d8;
    Validate(partial, mods, d8);
    REQUIRE(d8.Contains("generator list differs", S::Warning));
}

TEST_CASE("hdf: tooling augment command dry-run and check", "[hdf][tooling]")
{
    auto collector = MakeCollector();
    TempFolder temp;
    const auto file = temp.path / "HDF.json";
    WriteFile(file, HAND_WRITTEN);

    // --dry-run prints the diff and writes nothing
    std::ostringstream dry;
    AugmentOptions options;
    options.file   = file;
    options.dryRun = true;
    REQUIRE(AugmentCommand(options, collector, dry) == 0);
    REQUIRE(ReadFile(file) == HAND_WRITTEN);
    REQUIRE(dry.str().find("+      \"name\": \"IsPE\",") != std::string::npos);
    REQUIRE(dry.str().find("removed: predicates Orphan") != std::string::npos);
    // --check fails while the file is not up to date
    std::ostringstream check;
    options.dryRun = false;
    options.check  = true;
    REQUIRE(AugmentCommand(options, collector, check) == 1);
    REQUIRE(ReadFile(file) == HAND_WRITTEN);
    // a real run writes the file; afterwards --check passes (also with CRLF line ends) and validate exits 0
    std::ostringstream run;
    options.check = false;
    REQUIRE(AugmentCommand(options, collector, run) == 0);
    const auto written = ReadFile(file);
    REQUIRE(written != HAND_WRITTEN);
    std::ostringstream check2;
    options.check = true;
    REQUIRE(AugmentCommand(options, collector, check2) == 0);
    std::string crlf;
    for (const char c : written) {
        if (c == '\n')
            crlf += '\r';
        crlf += c;
    }
    WriteFile(file, crlf);
    std::ostringstream check3;
    REQUIRE(AugmentCommand(options, collector, check3) == 0);
    std::ostringstream validate;
    ValidateOptions vo;
    vo.file = file;
    REQUIRE(ValidateCommand(vo, collector, validate) == 0);
    // --output writes elsewhere
    std::ostringstream other;
    AugmentOptions to;
    to.file   = file;
    to.output = temp.path / "out.json";
    REQUIRE(AugmentCommand(to, collector, other) == 0);
    REQUIRE(NormalizeLineEnds(ReadFile(to.output)) == NormalizeLineEnds(written));
    // a broken file: validate reports and fails, augment writes nothing
    WriteFile(file, "{ broken");
    std::ostringstream broken;
    REQUIRE(ValidateCommand(vo, collector, broken) == 1);
    options.check = false;
    REQUIRE(AugmentCommand(options, collector, broken) == 1);
    REQUIRE(ReadFile(file) == "{ broken");
    // --json report
    WriteFile(file, written);
    std::ostringstream json;
    vo.json = true;
    REQUIRE(ValidateCommand(vo, collector, json) == 0);
    const auto report = ordered_json::parse(json.str(), nullptr, false);
    REQUIRE_FALSE(report.is_discarded());
    REQUIRE(report["errors"] == 0);
}

TEST_CASE("hdf: tooling unified diff", "[hdf][tooling]")
{
    const auto diff = UnifiedDiff("a\nb\nc\nd\ne\nf\ng\n", "a\nb\nc\nX\ne\nf\ng\n", "f.json");
    REQUIRE(diff.find("-d\n+X\n") != std::string::npos);
    REQUIRE(diff.find(" c\n") != std::string::npos);
    const auto none = UnifiedDiff("same\n", "same\n", "f");
    REQUIRE(none.find("\n+same") == std::string::npos);
    REQUIRE(none.find("\n-same") == std::string::npos);
}
