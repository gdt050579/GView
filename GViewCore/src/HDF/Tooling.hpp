#pragma once

// "GView hdf validate" and "GView hdf augment": HDF.json is hand-written only where it expresses knowledge (sorts,
// verdicts, rules, interpretation, stopping, "Manual" entries); its "predicates" and "actions" sections are generated
// from the modules that can produce them. Every predicate/action entry has "generator": [ ... ]:
//   "Plugin:<Name>" | "GenericPlugin:<Name>" | "SmartViewer:<Name>" | "Core:HDF" (module declarations)
//   "Rule:<RuleName>"                                                     (derived: the head of that assertion rule)
//   "Manual"                                                              (hand-written, never modified or removed)
// Neither command initializes the application: the plugins are loaded only to call their RegisterPlugin export.

#include "VocabularyRegistry.hpp"

namespace GView::HDF::Tooling
{
// the module walk, abstracted so that the tests inject fake modules
class VocabularyCollector
{
  public:
    // knownSort: sorts that exist outside the modules (built-ins and the "sorts" section of the file being checked)
    virtual std::vector<ModuleDeclarations> CollectAll(const std::function<bool(std::string_view)>& knownSort, std::vector<std::string>& warnings) = 0;
    virtual ~VocabularyCollector()                                                                                                                 = default;
};

// the core table + every Types/lib*.tpl and GenericPlugins/lib*.gpl next to the executable (the static table in the
// WebAssembly build)
class InstalledModulesCollector : public VocabularyCollector
{
  public:
    std::vector<ModuleDeclarations> CollectAll(const std::function<bool(std::string_view)>& knownSort, std::vector<std::string>& warnings) override;
};

enum class GeneratorKind : uint8 { Manual, Rule, Module };
GeneratorKind ClassifyGenerator(std::string_view generator);

// derived predicates: the head of every assertion rule, with the sorts rebuilt from the body ("Rule:<name>")
std::vector<ModuleDeclarations> InferDerivedPredicates(const nlohmann::ordered_json& document, const std::vector<ModuleDeclarations>& modules, Diagnostics& d);

// full validation: the specification itself, generator lists and the drift against the modules
void Validate(const nlohmann::ordered_json& document, const std::vector<ModuleDeclarations>& modules, Diagnostics& d);

struct AugmentResult {
    nlohmann::ordered_json document;
    std::vector<std::string> added, updated, removed;
};
// false (nothing to write) when the declarations are inconsistent (e.g. a derived predicate with two arities)
bool Augment(const nlohmann::ordered_json& input, const std::vector<ModuleDeclarations>& modules, AugmentResult& result, Diagnostics& d);

// the canonical text of a document (2-space indentation, '\n' line ends, trailing newline)
std::string Serialize(const nlohmann::ordered_json& document);
// minimal unified diff (line based) for --dry-run
std::string UnifiedDiff(std::string_view before, std::string_view after, std::string_view name);
// a text without '\r' (files may be checked out with CRLF line ends)
std::string NormalizeLineEnds(std::string_view text);

struct ValidateOptions {
    std::filesystem::path file{ "HDF.json" };
    bool json{ false };
};
struct AugmentOptions {
    std::filesystem::path file{ "HDF.json" };
    std::filesystem::path output; // empty: in place
    bool dryRun{ false };
    bool check{ false };
};
// return the process exit code; the output goes to out (the CLI passes std::cout)
int ValidateCommand(const ValidateOptions& options, VocabularyCollector& collector, std::ostream& out);
int AugmentCommand(const AugmentOptions& options, VocabularyCollector& collector, std::ostream& out);

// command line front-ends (GView::App::HDFValidate / HDFAugment)
int RunValidate(const std::vector<std::string>& arguments);
int RunAugment(const std::vector<std::string>& arguments);

} // namespace GView::HDF::Tooling
