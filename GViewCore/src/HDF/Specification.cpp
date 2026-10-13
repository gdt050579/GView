#include "Specification.hpp"

#include <charconv>
#include <cmath>

namespace GView::HDF
{
namespace
{
    inline bool IsIdentStart(char c)
    {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    }
    inline bool IsIdentChar(char c)
    {
        return IsIdentStart(c) || (c >= '0' && c <= '9');
    }
    inline void SkipSpaces(std::string_view text, size_t& pos)
    {
        while (pos < text.size() && (text[pos] == ' ' || text[pos] == '\t' || text[pos] == '\r' || text[pos] == '\n'))
            pos++;
    }
} // namespace

bool ParseLiteral(std::string_view text, ParsedLiteral& out, std::string& error)
{
    out.name.clear();
    out.terms.clear();
    size_t pos = 0;
    SkipSpaces(text, pos);
    if (pos >= text.size() || !IsIdentStart(text[pos])) {
        error = "expected a predicate or action name in '" + std::string(text) + "'";
        return false;
    }
    const size_t nameStart = pos;
    while (pos < text.size() && IsIdentChar(text[pos]))
        pos++;
    out.name = std::string(text.substr(nameStart, pos - nameStart));
    SkipSpaces(text, pos);
    if (pos >= text.size())
        return true; // "Name" == "Name()"
    if (text[pos] != '(') {
        error = "expected '(' after '" + out.name + "'";
        return false;
    }
    pos++;
    SkipSpaces(text, pos);
    if (pos < text.size() && text[pos] == ')') {
        pos++;
    } else {
        while (true) {
            SkipSpaces(text, pos);
            if (pos >= text.size()) {
                error = "unterminated literal '" + std::string(text) + "'";
                return false;
            }
            if (out.terms.size() >= MAX_ARITY) {
                error = "literal '" + out.name + "' has more than MAX_ARITY terms";
                return false;
            }
            ParsedTerm term;
            const char c = text[pos];
            if (c == '"') {
                pos++;
                term.kind   = ParsedTerm::Kind::String;
                bool closed = false;
                while (pos < text.size()) {
                    const char s = text[pos++];
                    if (s == '\\' && pos < text.size()) {
                        term.text.push_back(text[pos++]);
                        continue;
                    }
                    if (s == '"') {
                        closed = true;
                        break;
                    }
                    term.text.push_back(s);
                }
                if (!closed) {
                    error = "unterminated string in '" + std::string(text) + "'";
                    return false;
                }
            } else if (c == '-' || c == '+' || (c >= '0' && c <= '9') || c == '.') {
                term.kind         = ParsedTerm::Kind::Number;
                const size_t from = pos;
                pos++;
                while (pos < text.size()) {
                    const char n = text[pos];
                    if ((n >= '0' && n <= '9') || n == '.' || n == 'e' || n == 'E' ||
                        ((n == '-' || n == '+') && (text[pos - 1] == 'e' || text[pos - 1] == 'E'))) {
                        if (n == '.' || n == 'e' || n == 'E')
                            term.realSyntax = true;
                        pos++;
                        continue;
                    }
                    break;
                }
                term.text = std::string(text.substr(from, pos - from));
            } else if (IsIdentStart(c)) {
                const size_t from = pos;
                while (pos < text.size() && IsIdentChar(text[pos]))
                    pos++;
                term.text = std::string(text.substr(from, pos - from));
                term.kind = (term.text == "true" || term.text == "false") ? ParsedTerm::Kind::Bool : ParsedTerm::Kind::Variable;
            } else {
                error = "unexpected character '" + std::string(1, c) + "' in '" + std::string(text) + "'";
                return false;
            }
            out.terms.push_back(std::move(term));
            SkipSpaces(text, pos);
            if (pos < text.size() && text[pos] == ',') {
                pos++;
                continue;
            }
            if (pos < text.size() && text[pos] == ')') {
                pos++;
                break;
            }
            error = "expected ',' or ')' in '" + std::string(text) + "'";
            return false;
        }
    }
    SkipSpaces(text, pos);
    if (pos != text.size()) {
        error = "unexpected text after literal '" + std::string(text) + "'";
        return false;
    }
    return true;
}

std::string FormatParsedTerm(const ParsedTerm& term)
{
    if (term.kind == ParsedTerm::Kind::String)
        return "\"" + term.text + "\"";
    return term.text;
}

bool Specification::AddVerdictPredicate(PredicateId p, Signature& signature, std::string& error)
{
    if (!signature.predicates.IsValid(p)) {
        error = "unknown verdict predicate";
        return false;
    }
    auto& symbol = signature.predicates.GetMutable(p);
    if (symbol.arity.size() != 2 || signature.sorts.Kind(symbol.arity[0].sort) != SortKind::Subject ||
        signature.sorts.Kind(symbol.arity[1].sort) != SortKind::Real) {
        error = "verdict predicate '" + symbol.name + "' must have the arity Subject x Real";
        return false;
    }
    if (IsVerdict(p)) {
        error = "verdict predicate '" + symbol.name + "' is listed twice";
        return false;
    }
    symbol.isVerdict = true;
    verdictPredicates.push_back(p);
    return true;
}

bool Specification::CheckRuleName(std::string_view name, std::string& error) const
{
    if (name.empty()) {
        error = "rule without a name";
        return false;
    }
    if (assertionRuleNames.contains(name) || actionRuleNames.contains(name)) {
        error = "duplicate rule name '" + std::string(name) + "'";
        return false;
    }
    return true;
}

bool Specification::CompileTerms(
      RuleBody& rule,
      const ParsedLiteral& literal,
      const std::vector<Argument>& arity,
      bool isHead,
      const Signature& signature,
      ConstantPool& pool,
      uint32& termOffset,
      std::string& error)
{
    if (literal.terms.size() != arity.size()) {
        error = "'" + literal.name + "' expects " + std::to_string(arity.size()) + " argument(s), got " + std::to_string(literal.terms.size());
        return false;
    }
    termOffset = static_cast<uint32>(terms.size());
    for (size_t i = 0; i < literal.terms.size(); i++) {
        const auto& term    = literal.terms[i];
        const SortId sort   = arity[i].sort;
        const SortKind kind = signature.sorts.Kind(sort);
        const auto sortName = std::string(signature.sorts.Name(sort));
        const auto where    = "argument " + std::to_string(i + 1) + " of '" + literal.name + "'";
        switch (term.kind) {
        case ParsedTerm::Kind::Variable: {
            uint32 index = INVALID_INDEX;
            for (uint32 v = 0; v < rule.varCount; v++)
                if (rule.variableNames[v] == term.text)
                    index = v;
            if (index == INVALID_INDEX) {
                if (isHead) {
                    error = "unsafe rule: head variable '" + term.text + "' does not occur in the body";
                    return false;
                }
                if (rule.varCount >= MAX_RULE_VARIABLES) {
                    error = "more than MAX_RULE_VARIABLES variables";
                    return false;
                }
                index                = rule.varCount++;
                rule.varSorts[index] = sort;
                rule.variableNames.push_back(term.text);
            } else if (rule.varSorts[index] != sort) {
                error = "variable '" + term.text + "' is used with two sorts (" + std::string(signature.sorts.Name(rule.varSorts[index])) + " and " + sortName +
                        ")";
                return false;
            }
            terms.push_back(Term::Variable(static_cast<VariableIndex>(index)));
            break;
        }
        case ParsedTerm::Kind::String:
            if (kind != SortKind::String) {
                error = "ill-sorted term: " + where + " is " + sortName + ", got a string";
                return false;
            }
            terms.push_back(Term::Constant(pool.InternString(sort, term.text)));
            break;
        case ParsedTerm::Kind::Number: {
            std::optional<ConstantId> c;
            if (kind == SortKind::Int && !term.realSyntax) {
                int64 value      = 0;
                const char* from = term.text.data() + (term.text.starts_with('+') ? 1 : 0);
                auto res         = std::from_chars(from, term.text.data() + term.text.size(), value);
                if (res.ec == std::errc() && res.ptr == term.text.data() + term.text.size())
                    c = pool.InternInt(sort, value);
            } else if (kind == SortKind::Real) {
                char* end         = nullptr;
                const double real = std::strtod(term.text.c_str(), &end);
                if (end == term.text.c_str() + term.text.size() && std::isfinite(real))
                    c = pool.InternReal(sort, real);
            } else {
                error = "ill-sorted term: " + where + " is " + sortName + ", got the number " + term.text;
                return false;
            }
            if (!c.has_value()) {
                error = "invalid " + sortName + " constant '" + term.text + "' (" + where + ")";
                return false;
            }
            terms.push_back(Term::Constant(*c));
            break;
        }
        case ParsedTerm::Kind::Bool:
            if (kind != SortKind::Bool) {
                error = "ill-sorted term: " + where + " is " + sortName + ", got " + term.text;
                return false;
            }
            terms.push_back(Term::Constant(pool.InternBool(sort, term.text == "true")));
            break;
        }
        if (kind == SortKind::Subject && term.kind != ParsedTerm::Kind::Variable) {
            error = "ill-sorted term: " + where + " is a Subject (only variables are allowed)";
            return false;
        }
    }
    return true;
}

bool Specification::CompileBody(RuleBody& rule, std::span<const ParsedLiteral> body, const Signature& signature, ConstantPool& pool, std::string& error)
{
    if (body.size() > MAX_BODY_LITERALS) {
        error = "more than MAX_BODY_LITERALS body literals";
        return false;
    }
    rule.bodyOffset = static_cast<uint32>(bodyLiterals.size());
    rule.bodyCount  = static_cast<uint8>(body.size());
    for (const auto& parsed : body) {
        const auto p = signature.predicates.Find(parsed.name);
        if (p == INVALID_PREDICATE_ID) {
            error = signature.actions.Find(parsed.name) != INVALID_ACTION_ID ? "action '" + parsed.name + "' used in a rule body"
                                                                             : "unknown predicate '" + parsed.name + "'";
            return false;
        }
        Literal literal;
        literal.predicate = p;
        literal.arity     = static_cast<uint8>(parsed.terms.size());
        if (!CompileTerms(rule, parsed, signature.predicates.Get(p).arity, false, signature, pool, literal.termOffset, error))
            return false;
        bodyLiterals.push_back(literal);
    }
    return true;
}

bool Specification::AddAssertionRule(
      std::string_view name,
      std::span<const ParsedLiteral> body,
      const ParsedLiteral& head,
      std::string_view explanation,
      const Signature& signature,
      ConstantPool& pool,
      std::string& error)
{
    if (!CheckRuleName(name, error))
        return false;
    // keep the arenas unchanged when the rule is rejected
    const auto termsSize = terms.size(), literalsSize = bodyLiterals.size();
    AssertionRule rule;
    rule.name        = std::string(name);
    rule.explanation = std::string(explanation);
    bool ok          = CompileBody(rule, body, signature, pool, error);
    if (ok) {
        const auto p = signature.predicates.Find(head.name);
        if (p == INVALID_PREDICATE_ID) {
            error = signature.actions.Find(head.name) != INVALID_ACTION_ID ? "assertion rule with the action '" + head.name + "' as head"
                                                                           : "unknown head predicate '" + head.name + "'";
            ok    = false;
        } else if (signature.predicates.Get(p).IsCompletion() || signature.predicates.Get(p).isBuiltin) {
            error = "rule head '" + head.name + "' is reserved to the engine (built-in or completion predicate)";
            ok    = false;
        } else {
            rule.head.predicate = p;
            rule.head.arity     = static_cast<uint8>(head.terms.size());
            ok                  = CompileTerms(rule, head, signature.predicates.Get(p).arity, true, signature, pool, rule.head.termOffset, error);
            rule.isVerdictRule  = ok && IsVerdict(p);
        }
    }
    if (!ok) {
        terms.resize(termsSize);
        bodyLiterals.resize(literalsSize);
        error = "rule '" + std::string(name) + "': " + error;
        return false;
    }
    assertionRuleNames.emplace(rule.name, static_cast<RuleId>(assertionRules.size()));
    assertionRules.push_back(std::move(rule));
    return true;
}

bool Specification::AddActionRule(
      std::string_view name,
      std::span<const ParsedLiteral> body,
      const ParsedLiteral& head,
      std::string_view explanation,
      const Signature& signature,
      ConstantPool& pool,
      std::string& error)
{
    if (!CheckRuleName(name, error))
        return false;
    const auto termsSize = terms.size(), literalsSize = bodyLiterals.size();
    ActionRule rule;
    rule.name        = std::string(name);
    rule.explanation = std::string(explanation);
    bool ok          = CompileBody(rule, body, signature, pool, error);
    if (ok) {
        const auto a = signature.actions.Find(head.name);
        if (a == INVALID_ACTION_ID) {
            error = signature.predicates.Find(head.name) != INVALID_PREDICATE_ID ? "action rule with the predicate '" + head.name + "' as head"
                                                                                 : "unknown action '" + head.name + "'";
            ok    = false;
        } else {
            rule.head.action = a;
            rule.head.arity  = static_cast<uint8>(head.terms.size());
            ok               = CompileTerms(rule, head, signature.actions.Get(a).arity, true, signature, pool, rule.head.termOffset, error);
        }
    }
    if (!ok) {
        terms.resize(termsSize);
        bodyLiterals.resize(literalsSize);
        error = "rule '" + std::string(name) + "': " + error;
        return false;
    }
    actionRuleNames.emplace(rule.name, static_cast<RuleId>(actionRules.size()));
    actionRules.push_back(std::move(rule));
    return true;
}

namespace
{
    bool ParseAll(
          std::initializer_list<std::string_view> body,
          std::string_view head,
          std::vector<ParsedLiteral>& parsedBody,
          ParsedLiteral& parsedHead,
          std::string& error)
    {
        for (auto text : body) {
            ParsedLiteral literal;
            if (!ParseLiteral(text, literal, error))
                return false;
            parsedBody.push_back(std::move(literal));
        }
        return ParseLiteral(head, parsedHead, error);
    }
} // namespace

bool Specification::AddAssertionRule(
      std::string_view name,
      std::initializer_list<std::string_view> body,
      std::string_view head,
      const Signature& signature,
      ConstantPool& pool,
      std::string& error,
      std::string_view explanation)
{
    std::vector<ParsedLiteral> parsedBody;
    ParsedLiteral parsedHead;
    if (!ParseAll(body, head, parsedBody, parsedHead, error))
        return false;
    return AddAssertionRule(name, parsedBody, parsedHead, explanation, signature, pool, error);
}

bool Specification::AddActionRule(
      std::string_view name,
      std::initializer_list<std::string_view> body,
      std::string_view head,
      const Signature& signature,
      ConstantPool& pool,
      std::string& error,
      std::string_view explanation)
{
    std::vector<ParsedLiteral> parsedBody;
    ParsedLiteral parsedHead;
    if (!ParseAll(body, head, parsedBody, parsedHead, error))
        return false;
    return AddActionRule(name, parsedBody, parsedHead, explanation, signature, pool, error);
}

void Specification::AddBuiltinRules(const Signature& signature, ConstantPool& pool)
{
    std::string error;
    AddActionRule(
          "Builtin.ReanalyzeSelection", { "HasContent(x)" }, "ReanalyzeSelection(x)", signature, pool, error, "every subject with content can be reanalyzed");
}

void Specification::ComputeJoinOrders(RuleBody& rule) const
{
    const uint32 n = rule.bodyCount;
    auto order     = [&](uint32 first, uint8* out) {
        uint32 boundMask = 0; // bit per variable
        bool used[MAX_BODY_LITERALS]{};
        uint32 count = 0;
        auto bind    = [&](uint32 position) {
            used[position] = true;
            out[count++]   = static_cast<uint8>(position);
            for (const auto t : TermsOf(BodyLiteral(rule, position)))
                if (t.IsVariable())
                    boundMask |= 1u << t.Variable();
        };
        if (first != INVALID_INDEX)
            bind(first);
        while (count < n) {
            uint32 best     = INVALID_INDEX;
            int64 bestScore = 0;
            for (uint32 p = 0; p < n; p++) {
                if (used[p])
                    continue;
                const auto& literal = BodyLiteral(rule, p);
                const auto lt       = TermsOf(literal);
                uint32 boundOrConst = 0, unbound = 0, unboundMask = 0;
                for (const auto t : lt) {
                    if (t.IsConstant() || (boundMask & (1u << t.Variable())))
                        boundOrConst++;
                    else if ((unboundMask & (1u << t.Variable())) == 0) {
                        unboundMask |= 1u << t.Variable();
                        unbound++;
                    }
                }
                const bool firstIndexed = !lt.empty() && (lt[0].IsConstant() || (boundMask & (1u << lt[0].Variable())));
                // lexicographic: indexed first argument, most bound/constant positions, fewest new variables, lowest arity
                const int64 score = (firstIndexed ? 1LL << 40 : 0) + (static_cast<int64>(boundOrConst) << 24) - (static_cast<int64>(unbound) << 12) -
                                    static_cast<int64>(lt.size());
                if (best == INVALID_INDEX || score > bestScore) {
                    best      = p;
                    bestScore = score;
                }
            }
            bind(best);
        }
    };
    order(INVALID_INDEX, rule.fullOrder);
    rule.deltaOrder.assign(static_cast<size_t>(n) * n, 0);
    for (uint32 p = 0; p < n; p++)
        order(p, rule.deltaOrder.data() + static_cast<size_t>(p) * n);
}

void Specification::Compile(const Signature& signature)
{
    const auto predicateCount = signature.predicates.Count();
    assertionRulesByBodyPredicate.assign(predicateCount, {});
    actionRulesByBodyPredicate.assign(predicateCount, {});
    assertionRulesByHeadPredicate.assign(predicateCount, {});
    for (RuleId r = 0; r < assertionRules.size(); r++) {
        auto& rule = assertionRules[r];
        ComputeJoinOrders(rule);
        for (uint8 p = 0; p < rule.bodyCount; p++)
            assertionRulesByBodyPredicate[BodyLiteral(rule, p).predicate].push_back({ r, p });
        assertionRulesByHeadPredicate[rule.head.predicate].push_back(r);
        rule.isVerdictRule = IsVerdict(rule.head.predicate);
    }
    for (RuleId r = 0; r < actionRules.size(); r++) {
        auto& rule = actionRules[r];
        ComputeJoinOrders(rule);
        for (uint8 p = 0; p < rule.bodyCount; p++)
            actionRulesByBodyPredicate[BodyLiteral(rule, p).predicate].push_back({ r, p });
    }
}

std::string Specification::FormatLiteral(const RuleBody& rule, const Literal& literal, const Signature& signature, const ConstantPool& pool) const
{
    std::string result(signature.predicates.Get(literal.predicate).name);
    result.push_back('(');
    bool first = true;
    for (const auto t : TermsOf(literal)) {
        if (!first)
            result.append(", ");
        first = false;
        if (t.IsVariable())
            result.append(t.Variable() < rule.variableNames.size() ? rule.variableNames[t.Variable()] : "?");
        else
            result.append(pool.Format(t.Constant(), true));
    }
    result.push_back(')');
    return result;
}

std::string Specification::FormatRule(const AssertionRule& rule, const Signature& signature, const ConstantPool& pool) const
{
    std::string result;
    for (uint32 p = 0; p < rule.bodyCount; p++) {
        if (p > 0)
            result.append(", ");
        result.append(FormatLiteral(rule, BodyLiteral(rule, p), signature, pool));
    }
    result.append(rule.bodyCount ? " |- " : "|- ");
    result.append(FormatLiteral(rule, rule.head, signature, pool));
    return result;
}

std::string Specification::FormatRule(const ActionRule& rule, const Signature& signature, const ConstantPool& pool) const
{
    std::string result;
    for (uint32 p = 0; p < rule.bodyCount; p++) {
        if (p > 0)
            result.append(", ");
        result.append(FormatLiteral(rule, BodyLiteral(rule, p), signature, pool));
    }
    result.append(rule.bodyCount ? " ||- <" : "||- <");
    result.append(signature.actions.Get(rule.head.action).name);
    result.append(">(");
    bool first = true;
    for (const auto t : TermsOf(rule.head)) {
        if (!first)
            result.append(", ");
        first = false;
        if (t.IsVariable())
            result.append(t.Variable() < rule.variableNames.size() ? rule.variableNames[t.Variable()] : "?");
        else
            result.append(pool.Format(t.Constant(), true));
    }
    result.push_back(')');
    return result;
}

} // namespace GView::HDF
