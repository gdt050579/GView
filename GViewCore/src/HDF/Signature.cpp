#include "Signature.hpp"

namespace GView::HDF
{
std::string_view SortKindName(SortKind kind)
{
    switch (kind) {
    case SortKind::Subject:
        return "Subject";
    case SortKind::String:
        return "String";
    case SortKind::Int:
        return "Int";
    case SortKind::Real:
        return "Real";
    case SortKind::Bool:
        return "Bool";
    }
    return "?";
}

std::optional<SortKind> SortKindFromName(std::string_view name)
{
    if (name == "Subject")
        return SortKind::Subject;
    if (name == "String")
        return SortKind::String;
    if (name == "Int")
        return SortKind::Int;
    if (name == "Real")
        return SortKind::Real;
    if (name == "Bool")
        return SortKind::Bool;
    return std::nullopt;
}

bool DenotationTemplate::Compile(std::string_view source, std::span<const Argument> arity, std::string& error)
{
    text.clear();
    pieces.clear();
    text.reserve(source.size());
    auto flushLiteral = [this](size_t literalStart) {
        if (text.size() > literalStart)
            pieces.push_back({ static_cast<uint32>(literalStart), static_cast<uint32>(text.size() - literalStart), -1 });
    };
    size_t literalStart = 0;
    for (size_t i = 0; i < source.size(); i++) {
        const char ch = source[i];
        if (ch == '{' && i + 1 < source.size() && source[i + 1] == '{') {
            text.push_back('{');
            i++;
            continue;
        }
        if (ch == '}' && i + 1 < source.size() && source[i + 1] == '}') {
            text.push_back('}');
            i++;
            continue;
        }
        if (ch != '{') {
            text.push_back(ch);
            continue;
        }
        const auto close = source.find('}', i + 1);
        if (close == std::string_view::npos) {
            error = "unterminated placeholder in denotation";
            return false;
        }
        const auto name = source.substr(i + 1, close - i - 1);
        int32 position  = -1;
        for (size_t a = 0; a < arity.size(); a++)
            if (arity[a].name == name)
                position = static_cast<int32>(a);
        if (position < 0) {
            error = "denotation placeholder {" + std::string(name) + "} is not an argument name";
            return false;
        }
        flushLiteral(literalStart);
        pieces.push_back({ 0, 0, position });
        literalStart = text.size();
        i            = close;
    }
    flushLiteral(literalStart);
    return true;
}

std::optional<SortId> SortTable::Add(std::string_view name, SortKind kind, bool isBuiltin)
{
    if (name.empty() || byName.contains(name) || symbols.size() >= INVALID_SORT_ID)
        return std::nullopt;
    const auto id = static_cast<SortId>(symbols.size());
    symbols.push_back({ std::string(name), kind, isBuiltin });
    byName.emplace(std::string(name), id);
    return id;
}

GeneratorId GeneratorTable::Intern(std::string_view name)
{
    auto it = byName.find(name);
    if (it != byName.end())
        return it->second;
    const auto id = static_cast<GeneratorId>(names.size());
    names.emplace_back(name);
    byName.emplace(std::string(name), id);
    return id;
}

std::string Signature::CompletionPredicateName(std::string_view actionName)
{
    std::string name = "Done_";
    name.append(actionName);
    return name;
}

void Signature::AddBuiltins()
{
    subjectSort   = *sorts.Add("Subject", SortKind::Subject, true);
    stringSort    = *sorts.Add("String", SortKind::String, true);
    intSort       = *sorts.Add("Int", SortKind::Int, true);
    realSort      = *sorts.Add("Real", SortKind::Real, true);
    boolSort      = *sorts.Add("Bool", SortKind::Bool, true);
    urlSort       = *sorts.Add("URL", SortKind::String, true);
    coreGenerator = generators.Intern("Core:HDF");

    std::string error;
    const ArgumentDeclaration xy[]  = { { "y", "Subject" }, { "x", "Subject" } };
    const ArgumentDeclaration xn[]  = { { "x", "Subject" }, { "name", "String" } };
    const ArgumentDeclaration x[]   = { { "x", "Subject" } };
    const ArgumentDeclaration xo[]  = { { "x", "Subject" }, { "offset", "Int" } };
    const ArgumentDeclaration xsz[] = { { "x", "Subject" }, { "size", "Int" } };
    extractedFrom                   = *AddPredicate("ExtractedFrom", xy, "{y} was extracted from {x}", error, true);
    hasName                         = *AddPredicate("HasName", xn, "{x} is named {name}", error, true);
    hasContent                      = *AddPredicate("HasContent", x, "{x} has content", error, true);
    hasOffset                       = *AddPredicate("HasOffset", xo, "{x} starts at offset {offset} of its parent", error, true);
    hasSize                         = *AddPredicate("HasSize", xsz, "{x} has {size} bytes", error, true);
    reanalyzeSelection              = *AddAction("ReanalyzeSelection", x, "Reanalyze a selection of {x} as a new subject", true, error, true);
}

bool Signature::BuildArity(std::span<const ArgumentDeclaration> declared, std::vector<Argument>& out, std::string& error) const
{
    if (declared.size() > MAX_ARITY) {
        error = "arity exceeds MAX_ARITY (" + std::to_string(MAX_ARITY) + ")";
        return false;
    }
    out.clear();
    out.reserve(declared.size());
    for (const auto& arg : declared) {
        const auto sort = sorts.Find(arg.sort);
        if (sort == INVALID_SORT_ID) {
            error = "unknown sort '" + std::string(arg.sort) + "'";
            return false;
        }
        if (arg.name.empty()) {
            error = "argument without a name";
            return false;
        }
        for (const auto& previous : out)
            if (previous.name == arg.name) {
                error = "duplicate argument name '" + std::string(arg.name) + "'";
                return false;
            }
        out.push_back({ std::string(arg.name), sort });
    }
    return true;
}

std::optional<PredicateId> Signature::AddPredicate(
      std::string_view name, std::span<const ArgumentDeclaration> arity, std::string_view denotation, std::string& error, bool isBuiltin)
{
    PredicateSymbol symbol;
    symbol.name      = std::string(name);
    symbol.isBuiltin = isBuiltin;
    if (name.empty()) {
        error = "predicate without a name";
        return std::nullopt;
    }
    if (!BuildArity(arity, symbol.arity, error))
        return std::nullopt;
    symbol.denotationSource = std::string(denotation);
    if (!symbol.denotation.Compile(denotation, symbol.arity, error))
        return std::nullopt;
    if (isBuiltin)
        symbol.generators.push_back(coreGenerator);
    auto id = predicates.Add(std::move(symbol));
    if (!id.has_value())
        error = "duplicate predicate '" + std::string(name) + "'";
    return id;
}

std::optional<ActionId> Signature::AddAction(
      std::string_view name, std::span<const ArgumentDeclaration> arity, std::string_view denotation, bool repeatable, std::string& error, bool isBuiltin)
{
    ActionSymbol symbol;
    symbol.name       = std::string(name);
    symbol.repeatable = repeatable;
    symbol.isBuiltin  = isBuiltin;
    if (name.empty()) {
        error = "action without a name";
        return std::nullopt;
    }
    if (!BuildArity(arity, symbol.arity, error))
        return std::nullopt;
    symbol.denotationSource = std::string(denotation);
    if (!symbol.denotation.Compile(denotation, symbol.arity, error))
        return std::nullopt;
    if (isBuiltin)
        symbol.generators.push_back(coreGenerator);
    if (actions.Find(name) != INVALID_ACTION_ID) {
        error = "duplicate action '" + std::string(name) + "'";
        return std::nullopt;
    }
    if (predicates.Find(CompletionPredicateName(name)) != INVALID_PREDICATE_ID && !repeatable) {
        error = "predicate '" + CompletionPredicateName(name) + "' already exists (completion assertion of a non-repeatable action)";
        return std::nullopt;
    }
    auto id = actions.Add(std::move(symbol));
    if (!id.has_value()) {
        error = "duplicate action '" + std::string(name) + "'";
        return std::nullopt;
    }
    if (!repeatable) {
        // Done_a : same arity as a (completion assertion)
        std::vector<ArgumentDeclaration> doneArity;
        const auto& action = actions.Get(*id);
        for (const auto& arg : action.arity)
            doneArity.push_back({ arg.name, sorts.Name(arg.sort) });
        std::string doneDenotation = "Completed: ";
        doneDenotation.append(denotation);
        auto done = AddPredicate(CompletionPredicateName(name), doneArity, doneDenotation, error, false);
        if (!done.has_value())
            return std::nullopt;
        auto& doneSymbol        = predicates.GetMutable(*done);
        doneSymbol.completionOf = *id;
        doneSymbol.generators.push_back(coreGenerator);
        actions.GetMutable(*id).donePredicate = *done;
    }
    return id;
}

bool Signature::SameArity(const std::vector<Argument>& a, std::span<const ArgumentDeclaration> b) const
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); i++)
        if (a[i].name != b[i].name || sorts.Name(a[i].sort) != b[i].sort)
            return false;
    return true;
}

std::string Signature::FormatArity(const std::vector<Argument>& arity) const
{
    std::string result;
    for (const auto& arg : arity) {
        if (!result.empty())
            result.append(", ");
        result.append(arg.name).append(":").append(sorts.Name(arg.sort));
    }
    return result;
}

} // namespace GView::HDF
