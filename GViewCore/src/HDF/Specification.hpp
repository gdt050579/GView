#pragma once

// H = (R, A, V): safe assertion rules (lambda1..lambdan |- lambda), action rules (lambda1..lambdan ||- <a>(t1..tk)) and
// verdict predicates V, compiled into flat arenas with the indexes used by the entailment algorithms.

#include "ConstantPool.hpp"

namespace GView::HDF
{
// positive literal p(t1..tk); the terms are a range of Specification::terms
struct Literal {
    PredicateId predicate{ INVALID_PREDICATE_ID };
    uint32 termOffset{ 0 };
    uint8 arity{ 0 };
};
static_assert(sizeof(Literal) == 12);

// action specification <a>(t1..tk)
struct ActionSpecification {
    ActionId action{ INVALID_ACTION_ID };
    uint32 termOffset{ 0 };
    uint8 arity{ 0 };
};
static_assert(sizeof(ActionSpecification) == 12);

// common part of both rule kinds: the body literals, the variables and the compiled join orders
struct RuleBody {
    std::string name;
    std::string explanation;
    uint32 bodyOffset{ 0 }; // into Specification::bodyLiterals
    uint8 bodyCount{ 0 };
    uint8 varCount{ 0 };
    SortId varSorts[MAX_RULE_VARIABLES]{};
    uint8 fullOrder[MAX_BODY_LITERALS]{}; // join order when nothing is bound (body positions)
    std::vector<uint8> deltaOrder;        // bodyCount x bodyCount: row p = join order when position p is matched first
    std::vector<std::string> variableNames;
};

struct AssertionRule : RuleBody {
    Literal head;
    bool isVerdictRule{ false };
};

struct ActionRule : RuleBody {
    ActionSpecification head;
};

// a literal as written in HDF.json: Name(t1, .., tk) with t = identifier | "string" | number | true | false
struct ParsedTerm {
    enum class Kind : uint8 { Variable, String, Number, Bool };
    Kind kind{ Kind::Variable };
    bool realSyntax{ false }; // number written with '.' or an exponent
    std::string text;         // variable name, unescaped string, number text, "true"/"false"
};
struct ParsedLiteral {
    std::string name;
    std::vector<ParsedTerm> terms;
};
bool ParseLiteral(std::string_view text, ParsedLiteral& out, std::string& error);
std::string FormatParsedTerm(const ParsedTerm& term);

class Specification
{
  public:
    struct RuleOccurrence {
        RuleId rule;
        uint8 position; // body position
    };

    std::vector<Term> terms;
    std::vector<Literal> bodyLiterals;
    std::vector<AssertionRule> assertionRules;  // R
    std::vector<ActionRule> actionRules;        // A
    std::vector<PredicateId> verdictPredicates; // V

    // indexes (built by Compile, sized by the predicate count at that time)
    std::vector<std::vector<RuleOccurrence>> assertionRulesByBodyPredicate;
    std::vector<std::vector<RuleOccurrence>> actionRulesByBodyPredicate;
    std::vector<std::vector<RuleId>> assertionRulesByHeadPredicate;
    StringKeyMap<RuleId> assertionRuleNames;
    StringKeyMap<RuleId> actionRuleNames;

    bool AddVerdictPredicate(PredicateId p, Signature& signature, std::string& error);
    bool AddAssertionRule(
          std::string_view name,
          std::span<const ParsedLiteral> body,
          const ParsedLiteral& head,
          std::string_view explanation,
          const Signature& signature,
          ConstantPool& pool,
          std::string& error);
    bool AddActionRule(
          std::string_view name,
          std::span<const ParsedLiteral> body,
          const ParsedLiteral& head,
          std::string_view explanation,
          const Signature& signature,
          ConstantPool& pool,
          std::string& error);
    // text convenience (parses every literal first)
    bool AddAssertionRule(
          std::string_view name,
          std::initializer_list<std::string_view> body,
          std::string_view head,
          const Signature& signature,
          ConstantPool& pool,
          std::string& error,
          std::string_view explanation = {});
    bool AddActionRule(
          std::string_view name,
          std::initializer_list<std::string_view> body,
          std::string_view head,
          const Signature& signature,
          ConstantPool& pool,
          std::string& error,
          std::string_view explanation = {});
    // HasContent(x) ||- <ReanalyzeSelection>(x)
    void AddBuiltinRules(const Signature& signature, ConstantPool& pool);

    // builds the rule indexes and the join orders; must be called after the last Add*
    void Compile(const Signature& signature);

    inline std::span<const Term> TermsOf(const Literal& l) const
    {
        return { terms.data() + l.termOffset, l.arity };
    }
    inline std::span<const Term> TermsOf(const ActionSpecification& a) const
    {
        return { terms.data() + a.termOffset, a.arity };
    }
    inline const Literal& BodyLiteral(const RuleBody& rule, uint32 position) const
    {
        return bodyLiterals[rule.bodyOffset + position];
    }
    inline bool IsVerdict(PredicateId p) const
    {
        for (auto v : verdictPredicates)
            if (v == p)
                return true;
        return false;
    }
    inline std::span<const RuleOccurrence> AssertionRulesUsing(PredicateId p) const
    {
        return p < assertionRulesByBodyPredicate.size() ? std::span<const RuleOccurrence>(assertionRulesByBodyPredicate[p]) : std::span<const RuleOccurrence>();
    }
    inline std::span<const RuleOccurrence> ActionRulesUsing(PredicateId p) const
    {
        return p < actionRulesByBodyPredicate.size() ? std::span<const RuleOccurrence>(actionRulesByBodyPredicate[p]) : std::span<const RuleOccurrence>();
    }
    // "IsPE(x), HasImport(x, \"VirtualAlloc\") |- Head(x)" (original body order)
    std::string FormatRule(const AssertionRule& rule, const Signature& signature, const ConstantPool& pool) const;
    std::string FormatRule(const ActionRule& rule, const Signature& signature, const ConstantPool& pool) const;
    std::string FormatLiteral(const RuleBody& rule, const Literal& literal, const Signature& signature, const ConstantPool& pool) const;

  private:
    bool CompileBody(RuleBody& rule, std::span<const ParsedLiteral> body, const Signature& signature, ConstantPool& pool, std::string& error);
    bool CompileTerms(
          RuleBody& rule,
          const ParsedLiteral& literal,
          const std::vector<Argument>& arity,
          bool isHead,
          const Signature& signature,
          ConstantPool& pool,
          uint32& termOffset,
          std::string& error);
    bool CheckRuleName(std::string_view name, std::string& error) const;
    void ComputeJoinOrders(RuleBody& rule) const;
};

} // namespace GView::HDF
