#include "VocabularyRegistry.hpp"

namespace GView::HDF
{
std::string TypePluginGenerator(std::string_view pluginName)
{
    return "Plugin:" + std::string(pluginName);
}

std::string GenericPluginGenerator(std::string_view pluginName)
{
    return "GenericPlugin:" + std::string(pluginName);
}

CollectingRegistry::CollectingRegistry(std::string generator, std::function<bool(std::string_view)> knownSort) : isKnownSort(std::move(knownSort))
{
    declarations.generator = std::move(generator);
}

bool CollectingRegistry::Sort(std::string_view name, std::string_view kind)
{
    if (!IsIdentifier(name)) {
        declarations.errors.push_back("sort '" + std::string(name) + "' is not an identifier");
        return false;
    }
    if (!SortKindFromName(kind)) {
        declarations.errors.push_back("sort '" + std::string(name) + "' has the unknown kind '" + std::string(kind) + "'");
        return false;
    }
    for (const auto& s : declarations.sorts) {
        if (s.name == name) {
            if (s.kind == kind)
                return true; // first declaration wins
            declarations.errors.push_back("sort '" + std::string(name) + "' is declared with two kinds (" + s.kind + ", " + std::string(kind) + ")");
            return false;
        }
    }
    declarations.sorts.push_back({ std::string(name), std::string(kind) });
    return true;
}

bool CollectingRegistry::AddSymbol(bool isAction, std::string_view name, std::span<const Argument> arity, std::string_view denotation, bool repeatable)
{
    const char* what = isAction ? "action" : "predicate";
    if (!IsIdentifier(name)) {
        declarations.errors.push_back(std::string(what) + " '" + std::string(name) + "' is not an identifier");
        return false;
    }
    auto& list = isAction ? declarations.actions : declarations.predicates;
    for (const auto& existing : list)
        if (existing.name == name) {
            declarations.errors.push_back("duplicate " + std::string(what) + " '" + std::string(name) + "'");
            return false;
        }
    if (arity.size() > MAX_ARITY) {
        declarations.errors.push_back(std::string(what) + " '" + std::string(name) + "' has more than MAX_ARITY arguments");
        return false;
    }
    DeclaredSymbol symbol;
    symbol.name       = std::string(name);
    symbol.denotation = std::string(denotation);
    symbol.repeatable = repeatable;
    for (const auto& arg : arity) {
        bool known = SortKindFromName(arg.sort).has_value() || arg.sort == "URL" || (isKnownSort && isKnownSort(arg.sort));
        for (const auto& s : declarations.sorts)
            known |= s.name == arg.sort;
        if (!known) {
            declarations.errors.push_back(std::string(what) + " '" + std::string(name) + "' uses the unknown sort '" + std::string(arg.sort) + "'");
            return false;
        }
        if (!IsIdentifier(arg.name)) {
            declarations.errors.push_back(std::string(what) + " '" + std::string(name) + "' has an argument name that is not an identifier");
            return false;
        }
        symbol.arity.push_back({ std::string(arg.name), std::string(arg.sort) });
    }
    list.push_back(std::move(symbol));
    return true;
}

bool CollectingRegistry::Predicate(std::string_view name, std::initializer_list<Argument> arity, std::string_view denotation)
{
    return AddSymbol(false, name, std::span<const Argument>(arity.begin(), arity.size()), denotation, false);
}

bool CollectingRegistry::Action(std::string_view name, std::initializer_list<Argument> arity, std::string_view denotation, bool repeatable)
{
    return AddSymbol(true, name, std::span<const Argument>(arity.begin(), arity.size()), denotation, repeatable);
}

RuntimeRegistry::RuntimeRegistry(std::string generator, const Signature& signature)
    : CollectingRegistry(std::move(generator), [&signature](std::string_view sort) { return signature.sorts.Find(sort) != INVALID_SORT_ID; })
{
}

namespace
{
    std::vector<ArgumentDeclaration> AsDeclarations(const DeclaredSymbol& symbol)
    {
        std::vector<ArgumentDeclaration> result;
        for (const auto& a : symbol.arity)
            result.push_back({ a.name, a.sort });
        return result;
    }
    void Mark(std::vector<uint8>& flags, uint32 id)
    {
        if (flags.size() <= id)
            flags.resize(static_cast<size_t>(id) + 1, 0);
        flags[id] = 1;
    }
} // namespace

DriftReport RuntimeRegistry::Apply(LoadedSpecification& spec, std::vector<uint8>& rejectedPredicates, std::vector<uint8>& rejectedActions)
{
    DriftReport report;
    auto& sig            = spec.signature;
    const auto generator = sig.generators.Intern(declarations.generator);
    for (const auto& s : declarations.sorts)
        if (sig.sorts.Find(s.name) == INVALID_SORT_ID)
            if (sig.sorts.Add(s.name, *SortKindFromName(s.kind)))
                report.appended.push_back("sort " + s.name);
    auto addGenerator = [generator](std::vector<GeneratorId>& list) {
        if (std::find(list.begin(), list.end(), generator) == list.end())
            list.push_back(generator);
    };
    for (const auto& p : declarations.predicates) {
        const auto args = AsDeclarations(p);
        const auto id   = sig.predicates.Find(p.name);
        if (id == INVALID_PREDICATE_ID) {
            std::string error;
            if (auto added = sig.AddPredicate(p.name, args, p.denotation, error)) {
                addGenerator(sig.predicates.GetMutable(*added).generators);
                report.appended.push_back("predicate " + p.name);
            } else {
                report.rejected.push_back("predicate " + p.name + ": " + error);
            }
            continue;
        }
        if (!sig.SameArity(sig.predicates.Get(id).arity, args)) {
            Mark(rejectedPredicates, id);
            report.rejected.push_back("predicate " + p.name + " (HDF.json: " + sig.FormatArity(sig.predicates.Get(id).arity) + ")");
            continue;
        }
        addGenerator(sig.predicates.GetMutable(id).generators);
    }
    for (const auto& a : declarations.actions) {
        const auto args = AsDeclarations(a);
        const auto id   = sig.actions.Find(a.name);
        if (id == INVALID_ACTION_ID) {
            std::string error;
            if (auto added = sig.AddAction(a.name, args, a.denotation, a.repeatable, error)) {
                addGenerator(sig.actions.GetMutable(*added).generators);
                report.appended.push_back("action " + a.name);
            } else {
                report.rejected.push_back("action " + a.name + ": " + error);
            }
            continue;
        }
        if (!sig.SameArity(sig.actions.Get(id).arity, args) || sig.actions.Get(id).repeatable != a.repeatable) {
            Mark(rejectedActions, id);
            report.rejected.push_back("action " + a.name + " (HDF.json: " + sig.FormatArity(sig.actions.Get(id).arity) + ")");
            continue;
        }
        addGenerator(sig.actions.GetMutable(id).generators);
    }
    for (const auto& e : declarations.errors)
        report.rejected.push_back(e);
    return report;
}

namespace
{
    // the builder interface takes initializer lists (plugin-friendly); dispatch a runtime arity onto one
    bool Declare(
          VocabularyBuilderInterface& b,
          bool isAction,
          std::string_view name,
          const std::vector<VocabularyBuilderInterface::Argument>& a,
          std::string_view den,
          bool repeatable)
    {
        using A   = VocabularyBuilderInterface::Argument;
        auto call = [&](std::initializer_list<A> arity) { return isAction ? b.Action(name, arity, den, repeatable) : b.Predicate(name, arity, den); };
        switch (a.size()) {
        case 0:
            return call({});
        case 1:
            return call({ a[0] });
        case 2:
            return call({ a[0], a[1] });
        case 3:
            return call({ a[0], a[1], a[2] });
        case 4:
            return call({ a[0], a[1], a[2], a[3] });
        case 5:
            return call({ a[0], a[1], a[2], a[3], a[4] });
        case 6:
            return call({ a[0], a[1], a[2], a[3], a[4], a[5] });
        case 7:
            return call({ a[0], a[1], a[2], a[3], a[4], a[5], a[6] });
        case 8:
            return call({ a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7] });
        default:
            return false;
        }
    }
} // namespace

void DeclareBuiltins(VocabularyBuilderInterface& builder)
{
    // the same symbols as Signature::AddBuiltins (single source); the completion predicates Done_a are derived from the
    // non-repeatable actions by the tooling
    Signature sig;
    sig.AddBuiltins();
    std::vector<VocabularyBuilderInterface::Argument> arity;
    for (PredicateId p = 0; p < sig.predicates.Count(); p++) {
        const auto& symbol = sig.predicates.Get(p);
        if (!symbol.isBuiltin)
            continue;
        arity.clear();
        for (const auto& a : symbol.arity)
            arity.push_back({ a.name, sig.sorts.Name(a.sort) });
        Declare(builder, false, symbol.name, arity, symbol.denotationSource, false);
    }
    for (ActionId a = 0; a < sig.actions.Count(); a++) {
        const auto& symbol = sig.actions.Get(a);
        arity.clear();
        for (const auto& arg : symbol.arity)
            arity.push_back({ arg.name, sig.sorts.Name(arg.sort) });
        Declare(builder, true, symbol.name, arity, symbol.denotationSource, symbol.repeatable);
    }
}

} // namespace GView::HDF
