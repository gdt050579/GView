#pragma once

// Sigma_HDF = (S, P, A): sorts, predicate symbols p : s1 x .. x sk and action symbols a : s1 x .. x sk.

#include "Term.hpp"

#include <optional>
#include <span>

namespace GView::HDF
{
enum class SortKind : uint8 { Subject = 0, String = 1, Int = 2, Real = 3, Bool = 4 };

std::string_view SortKindName(SortKind kind);
std::optional<SortKind> SortKindFromName(std::string_view name);

// a position of an arity: the argument name (used by denotation placeholders) and its sort
struct Argument {
    std::string name;
    SortId sort{ INVALID_SORT_ID };
};

// den(.) template: "{x} has section {section}" compiled into literal text pieces and argument positions
struct DenotationTemplate {
    struct Piece {
        uint32 offset; // into text (literal piece) - unused for argument pieces
        uint32 length;
        int32 argument; // -1 -> literal text, otherwise the argument position
    };
    std::string text;
    std::vector<Piece> pieces;

    // "{{" / "}}" escape braces; unknown placeholder names are reported through error (returns false)
    bool Compile(std::string_view source, std::span<const Argument> arity, std::string& error);
    inline bool Empty() const
    {
        return pieces.empty();
    }
};

struct SortSymbol {
    std::string name;
    SortKind kind{ SortKind::String };
    bool isBuiltin{ false };
};

struct PredicateSymbol {
    std::string name;
    std::vector<Argument> arity;
    DenotationTemplate denotation;
    std::string denotationSource; // as written (tooling / display)
    std::vector<GeneratorId> generators;
    ActionId completionOf{ INVALID_ACTION_ID }; // Done_a of this action (otherwise INVALID_ACTION_ID)
    bool isVerdict{ false };
    bool isBuiltin{ false };

    inline uint8 Arity() const
    {
        return static_cast<uint8>(arity.size());
    }
    inline bool IsCompletion() const
    {
        return completionOf != INVALID_ACTION_ID;
    }
};

struct ActionSymbol {
    std::string name;
    std::vector<Argument> arity;
    DenotationTemplate denotation;
    std::string denotationSource;
    std::vector<GeneratorId> generators;
    PredicateId donePredicate{ INVALID_PREDICATE_ID }; // Done_a (non-repeatable actions only)
    bool repeatable{ false };
    bool isBuiltin{ false };

    inline uint8 Arity() const
    {
        return static_cast<uint8>(arity.size());
    }
};

class SortTable
{
    std::vector<SortSymbol> symbols;
    StringKeyMap<SortId> byName;

  public:
    std::optional<SortId> Add(std::string_view name, SortKind kind, bool isBuiltin = false);
    inline SortId Find(std::string_view name) const
    {
        auto it = byName.find(name);
        return it == byName.end() ? INVALID_SORT_ID : it->second;
    }
    inline uint32 Count() const
    {
        return static_cast<uint32>(symbols.size());
    }
    inline const SortSymbol& Get(SortId id) const
    {
        return symbols[id];
    }
    inline SortKind Kind(SortId id) const
    {
        return symbols[id].kind;
    }
    inline std::string_view Name(SortId id) const
    {
        return id < symbols.size() ? std::string_view(symbols[id].name) : std::string_view("?");
    }
};

class GeneratorTable
{
    std::vector<std::string> names;
    StringKeyMap<GeneratorId> byName;

  public:
    GeneratorId Intern(std::string_view name);
    inline std::string_view Name(GeneratorId id) const
    {
        return id < names.size() ? std::string_view(names[id]) : std::string_view("?");
    }
    inline uint32 Count() const
    {
        return static_cast<uint32>(names.size());
    }
};

template <typename Id, typename Symbol>
class SymbolTable
{
    std::vector<Symbol> symbols;
    StringKeyMap<Id> byName;

  public:
    // nullopt when the name already exists
    std::optional<Id> Add(Symbol symbol)
    {
        if (byName.contains(symbol.name))
            return std::nullopt;
        const Id id = static_cast<Id>(symbols.size());
        byName.emplace(symbol.name, id);
        symbols.push_back(std::move(symbol));
        return id;
    }
    inline Id Find(std::string_view name) const
    {
        auto it = byName.find(name);
        return it == byName.end() ? static_cast<Id>(INVALID_INDEX) : it->second;
    }
    inline uint32 Count() const
    {
        return static_cast<uint32>(symbols.size());
    }
    inline bool IsValid(Id id) const
    {
        return id < symbols.size();
    }
    inline const Symbol& Get(Id id) const
    {
        return symbols[id];
    }
    inline Symbol& GetMutable(Id id)
    {
        return symbols[id];
    }
};
using PredicateTable = SymbolTable<PredicateId, PredicateSymbol>;
using ActionTable    = SymbolTable<ActionId, ActionSymbol>;

struct ArgumentDeclaration {
    std::string_view name;
    std::string_view sort;
};

class Signature
{
  public:
    SortTable sorts;
    PredicateTable predicates;
    ActionTable actions;
    GeneratorTable generators;

    // built-in sorts (always present, ids fixed by AddBuiltins)
    SortId subjectSort{ INVALID_SORT_ID }, stringSort{ INVALID_SORT_ID }, intSort{ INVALID_SORT_ID }, realSort{ INVALID_SORT_ID }, boolSort{ INVALID_SORT_ID },
          urlSort{ INVALID_SORT_ID };
    // built-in predicates and action
    PredicateId extractedFrom{ INVALID_PREDICATE_ID }, hasName{ INVALID_PREDICATE_ID }, hasContent{ INVALID_PREDICATE_ID }, hasOffset{ INVALID_PREDICATE_ID },
          hasSize{ INVALID_PREDICATE_ID };
    ActionId reanalyzeSelection{ INVALID_ACTION_ID };
    GeneratorId coreGenerator{ 0 };

    // Subject, String, Int, Real, Bool, URL, ExtractedFrom, HasName, HasContent, HasOffset, HasSize, ReanalyzeSelection
    void AddBuiltins();

    // declares a predicate; returns nullopt and fills error on duplicate name / unknown sort / arity > MAX_ARITY / bad denotation
    std::optional<PredicateId> AddPredicate(
          std::string_view name, std::span<const ArgumentDeclaration> arity, std::string_view denotation, std::string& error, bool isBuiltin = false);
    // declares an action (and Done_<name> for a non-repeatable one)
    std::optional<ActionId> AddAction(
          std::string_view name,
          std::span<const ArgumentDeclaration> arity,
          std::string_view denotation,
          bool repeatable,
          std::string& error,
          bool isBuiltin = false);

    bool SameArity(const std::vector<Argument>& a, std::span<const ArgumentDeclaration> b) const;
    std::string FormatArity(const std::vector<Argument>& arity) const; // "x:Subject, size:Int"
    static std::string CompletionPredicateName(std::string_view actionName);

  private:
    bool BuildArity(std::span<const ArgumentDeclaration> declared, std::vector<Argument>& out, std::string& error) const;
};

} // namespace GView::HDF
