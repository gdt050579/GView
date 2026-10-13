#pragma once

// Module-declared vocabulary (plan section 15): every module (type plugin, generic plugin, smart viewer, the engine itself)
// declares the predicate and action symbols it can produce through GView::PluginRegistry::HDFVocabulary().
//   CollectingRegistry - records the declarations tagged with the module's generator name ("Plugin:PE", ...)
//   RuntimeRegistry    - the engine's registry: after collecting, checks the declarations against the loaded HDF.json
//                        (unknown symbols are appended with a warning, arity/sort mismatches are rejected)

#include "SpecificationLoader.hpp"

namespace GView::HDF
{
struct DeclaredArgument {
    std::string name;
    std::string sort;
    bool operator==(const DeclaredArgument&) const = default;
};
struct DeclaredSymbol {
    std::string name;
    std::vector<DeclaredArgument> arity;
    std::string denotation;
    bool repeatable{ false }; // actions only
};
struct DeclaredSort {
    std::string name;
    std::string kind;
};
struct ModuleDeclarations {
    std::string generator; // "Plugin:PE", "GenericPlugin:Hashes", "SmartViewer:Buffer", "Core:HDF"
    std::vector<DeclaredSort> sorts;
    std::vector<DeclaredSymbol> predicates;
    std::vector<DeclaredSymbol> actions;
    std::vector<std::string> errors;
};

// generator names
std::string TypePluginGenerator(std::string_view pluginName);    // "Plugin:<Name>"
std::string GenericPluginGenerator(std::string_view pluginName); // "GenericPlugin:<Name>"

class CollectingRegistry : public GView::PluginRegistry, public VocabularyBuilderInterface
{
  protected:
    ModuleDeclarations declarations;
    std::function<bool(std::string_view)> isKnownSort; // sorts that exist outside this module (built-ins, HDF.json, ...)

  public:
    explicit CollectingRegistry(std::string generator, std::function<bool(std::string_view)> knownSort = {});
    VocabularyBuilderInterface& HDFVocabulary() override
    {
        return *this;
    }
    bool Predicate(std::string_view name, std::initializer_list<Argument> arity, std::string_view denotation) override;
    bool Action(std::string_view name, std::initializer_list<Argument> arity, std::string_view denotation, bool repeatable = false) override;
    bool Sort(std::string_view name, std::string_view kind) override;
    // span-based variants (tests and the core table)
    bool AddSymbol(bool isAction, std::string_view name, std::span<const Argument> arity, std::string_view denotation, bool repeatable);

    inline const ModuleDeclarations& Declarations() const
    {
        return declarations;
    }
    inline ModuleDeclarations TakeDeclarations()
    {
        return std::move(declarations);
    }
};

// the engine's view: the result of the runtime drift check of one module
struct DriftReport {
    std::vector<std::string> appended; // symbols unknown to HDF.json, added in memory (no rule references them)
    std::vector<std::string> rejected; // symbols whose arity/sorts differ from HDF.json (their disclosures are rejected)
};

class RuntimeRegistry : public CollectingRegistry
{
  public:
    RuntimeRegistry(std::string generator, const Signature& signature);
    // applies the declarations to spec: unknown sorts/predicates/actions are appended, mismatches are reported through
    // rejectedPredicates / rejectedActions (indexed by id, grown as needed)
    DriftReport Apply(LoadedSpecification& spec, std::vector<uint8>& rejectedPredicates, std::vector<uint8>& rejectedActions);
};

// declarations of the core modules ("Core:HDF" and every smart viewer), see CoreVocabulary.cpp
struct CoreModule {
    std::string_view generator;
    void (*declare)(VocabularyBuilderInterface& builder);
};
std::span<const CoreModule> CoreModules();
// Core:HDF - the built-in predicates and action of the engine
void DeclareBuiltins(VocabularyBuilderInterface& builder);

} // namespace GView::HDF
