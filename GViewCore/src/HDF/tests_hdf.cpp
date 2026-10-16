// Unit tests of the Hybrid Disclosure Framework core (GViewCore/src/HDF). Every formal definition of the chapter is
// checked by at least one test (see the test matrix in plans/HDF_IMPLEMENTATION.md).

#include "SpecificationLoader.hpp"
#include "Explanation.hpp"

#include <catch.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <cstdio>
#include <functional>
#include <iostream>
#include <map>
#include <random>
#include <set>

using namespace GView::HDF;

namespace
{
// A specification used by most tests
constexpr std::string_view CORE_SPEC = R"JSON({
  "sorts": [ { "name": "Domain", "kind": "String" } ],
  "actions": [
    { "name": "Unpack", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "Unpack {x}" },
    { "name": "Rescan", "arity": [ { "name": "x", "sort": "Subject" } ], "repeatable": true, "denotation": "Rescan {x}" }
  ],
  "predicates": [
    { "name": "IsPE", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} is a PE file" },
    { "name": "IsArchive", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} is an archive" },
    { "name": "ContainsExecutable", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} contains an executable" },
    { "name": "HasImport", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "api", "sort": "String" } ], "denotation": "{x} imports {api}" },
    { "name": "HasSection", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "name", "sort": "String" }, { "name": "size", "sort": "Int" } ], "denotation": "{x} has section {name} ({size} bytes)" },
    { "name": "ContactsDomain", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "d", "sort": "Domain" } ] },
    { "name": "Injection", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} can inject code" },
    { "name": "IsSigned", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} is signed" },
    { "name": "HasValidSignature", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} has a valid signature" },
    { "name": "HasMaliciousness", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "score", "sort": "Real" } ], "denotation": "{x} has maliciousness {score}" },
    { "name": "HasBenignity", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "score", "sort": "Real" } ], "denotation": "{x} has benignity {score}" }
  ],
  "verdicts": [ "HasMaliciousness", "HasBenignity" ],
  "assertion_rules": [
    { "name": "Contains", "body": [ "ExtractedFrom(y, x)", "IsPE(y)" ], "head": "ContainsExecutable(x)" },
    { "name": "Inject", "body": [ "IsPE(x)", "HasImport(x, \"VirtualAlloc\")", "HasImport(x, \"WriteProcessMemory\")" ], "head": "Injection(x)", "explanation": "allocates and writes memory in another process" },
    { "name": "Verdict", "body": [ "Injection(x)" ], "head": "HasMaliciousness(x, 0.8)" },
    { "name": "DownloaderImport", "body": [ "HasImport(x, \"URLDownloadToFileA\")" ], "head": "HasMaliciousness(x, 0.6)" },
    { "name": "Signed", "body": [ "IsSigned(x)", "HasValidSignature(x)" ], "head": "HasBenignity(x, 0.85)" }
  ],
  "action_rules": [
    { "name": "UnpackArchive", "body": [ "IsArchive(x)" ], "head": "Unpack(x)" },
    { "name": "RescanPE", "body": [ "IsPE(x)" ], "head": "Rescan(x)" }
  ],
  "interpretation": {
    "outcomes": [ "Malicious", "Benign" ],
    "labels": [
      { "outcome": "Malicious", "propagate": true, "settle": "immediate",
        "clauses": [ { "present": "HasMaliciousness", "op": ">=", "value": 0.70 }, { "absent": "HasBenignity", "op": ">=", "value": 0.70 } ] },
      { "outcome": "Benign", "propagate": false, "settle": "exhaustion",
        "clauses": [ { "present": "HasBenignity", "op": ">=", "value": 0.70 }, { "absent": "HasMaliciousness", "op": ">", "value": 0.30 } ] }
    ],
    "aggregation": "default"
  },
  "stopping": { "policy": "conclusive", "max_steps": 0 }
})JSON";

struct LambdaExecutor : ActionExecutorInterface {
    std::function<ActionStatus(const GroundActionView&, const ActionInput*, DisclosureSink&)> fn;
    ActionStatus Execute(const GroundActionView& action, const ActionInput* input, DisclosureSink& out) override
    {
        return fn(action, input, out);
    }
};

// SessionHost with one executor per action symbol
struct Fixture : SessionHost {
    std::unique_ptr<LoadedSpecification> spec;
    SubjectRegistry registry;
    std::vector<std::unique_ptr<DisclosureSession>> sessions;
    std::map<ActionId, ActionExecutorInterface*> executors;
    uint32 transitionsSeen{ 0 };

    explicit Fixture(std::string_view json = CORE_SPEC)
    {
        Diagnostics d;
        spec = LoadSpecificationText(json, d);
        INFO(d.ToText());
        REQUIRE(spec);
        REQUIRE_FALSE(d.HasErrors());
    }
    explicit Fixture(std::unique_ptr<LoadedSpecification> s) : spec(std::move(s))
    {
    }
    DisclosureSession& NewSession(StoppingPolicy policy = {}, uint32 maxDerived = DEFAULT_MAX_DERIVED)
    {
        sessions.push_back(std::make_unique<DisclosureSession>(
              static_cast<uint32>(sessions.size()),
              spec->signature,
              spec->specification,
              spec->interpretation,
              spec->pool,
              registry,
              this,
              policy,
              maxDerived));
        return *sessions.back();
    }
    PredicateId P(std::string_view name) const
    {
        auto p = spec->signature.predicates.Find(name);
        REQUIRE(p != INVALID_PREDICATE_ID);
        return p;
    }
    ActionId A(std::string_view name) const
    {
        auto a = spec->signature.actions.Find(name);
        REQUIRE(a != INVALID_ACTION_ID);
        return a;
    }
    ActionExecutorInterface* ExecutorFor(const DisclosureSession& session, GroundActionId beta) override
    {
        auto it = executors.find(session.Enabled().Get(beta).action);
        return it == executors.end() ? nullptr : it->second;
    }
    void OnTransition(DisclosureSession&, uint32) override
    {
        transitionsSeen++;
    }
    ConstantId S(DisclosureSession& session, SubjectId s) const
    {
        return session.SubjectConstant(s);
    }
    ConstantId Str(std::string_view text)
    {
        return spec->pool.InternString(spec->signature.stringSort, text);
    }
};

std::set<std::vector<uint32>> AsSet(const AssertionBase& gamma)
{
    std::set<std::vector<uint32>> result;
    for (AssertionId a = 0; a < gamma.Size(); a++) {
        std::vector<uint32> row{ gamma.Predicate(a) };
        for (auto c : gamma.Args(a))
            row.push_back(c);
        result.insert(row);
    }
    return result;
}

StoppingPolicy ManualPolicy()
{
    StoppingPolicy policy;
    policy.kind = StoppingPolicyKind::Manual;
    return policy;
}

GroundActionId FindBeta(const DisclosureSession& s, ActionId a, SubjectId subject)
{
    const ConstantId c = s.SubjectConstant(subject);
    return s.Enabled().Find(a, std::span<const ConstantId>(&c, 1));
}

uint64 CollidingHash(PredicateId, const ConstantId*, uint32)
{
    return 42; // every assertion lands in the same probe chain
}
} // namespace

// ---------------------------------------------------------------------------------------------------------------------
// constants, terms, signature
// ---------------------------------------------------------------------------------------------------------------------

TEST_CASE("hdf: constant interning", "[hdf]")
{
    Signature sig;
    sig.AddBuiltins();
    ConstantPool pool(sig.sorts);
    const auto a1 = pool.InternString(sig.stringSort, "evil.example");
    const auto a2 = pool.InternString(sig.stringSort, std::string("evil.") + "example");
    REQUIRE(a1 == a2);
    // same bits (same StringId), different sorts => different constants
    const auto url = pool.InternString(sig.urlSort, "evil.example");
    REQUIRE(url != a1);
    REQUIRE(pool.Sort(url) == sig.urlSort);
    REQUIRE(pool.AsString(url) == "evil.example");
    // Int 1 and Bool true share bits but not sorts
    REQUIRE(*pool.InternInt(sig.intSort, 1) != pool.InternBool(sig.boolSort, true));
    // -0.0 == 0.0, NaN / infinities rejected
    REQUIRE(*pool.InternReal(sig.realSort, -0.0) == *pool.InternReal(sig.realSort, 0.0));
    REQUIRE_FALSE(pool.InternReal(sig.realSort, std::numeric_limits<double>::quiet_NaN()).has_value());
    REQUIRE_FALSE(pool.InternReal(sig.realSort, std::numeric_limits<double>::infinity()).has_value());
    // ArgValue conversions by sort kind
    REQUIRE(pool.Intern(sig.intSort, ArgValue(uint64(5))).has_value());
    REQUIRE_FALSE(pool.Intern(sig.intSort, ArgValue(uint64(0xFFFFFFFFFFFFFFFFull))).has_value());
    REQUIRE_FALSE(pool.Intern(sig.intSort, ArgValue("12")).has_value());
    REQUIRE_FALSE(pool.Intern(sig.stringSort, ArgValue(12)).has_value());
    REQUIRE(pool.Intern(sig.realSort, ArgValue(3)).has_value()); // Int -> Real is representable
    REQUIRE(pool.AsReal(*pool.Intern(sig.realSort, ArgValue(0.75))) == 0.75);
    REQUIRE(pool.Format(*pool.Intern(sig.realSort, ArgValue(0.75)), false) == "0.75");

    // views stay valid while the arena grows (chunked storage)
    std::vector<std::pair<ConstantId, std::string_view>> views;
    for (int i = 0; i < 20000; i++) {
        const auto text = "string-" + std::to_string(i) + std::string(static_cast<size_t>(i % 50), 'x');
        const auto c    = pool.InternString(sig.stringSort, text);
        views.emplace_back(c, pool.AsString(c));
    }
    const std::string big(200000, 'B'); // larger than a chunk
    const auto bigId = pool.InternString(sig.stringSort, big);
    for (int i = 0; i < 20000; i++) {
        const auto text = "string-" + std::to_string(i) + std::string(static_cast<size_t>(i % 50), 'x');
        REQUIRE(views[i].second == text);
        REQUIRE(pool.FindString(sig.stringSort, text) == views[i].first);
    }
    REQUIRE(pool.AsString(bigId) == big);
}

TEST_CASE("hdf: term encoding and struct sizes", "[hdf]")
{
    const auto v = Term::Variable(7);
    const auto c = Term::Constant(123456);
    REQUIRE(v.IsVariable());
    REQUIRE(v.Variable() == 7);
    REQUIRE(c.IsConstant());
    REQUIRE(c.Constant() == 123456);
    STATIC_REQUIRE(sizeof(Term) == 4);
    STATIC_REQUIRE(sizeof(Literal) == 12);
    STATIC_REQUIRE(sizeof(ActionSpecification) == 12);
    STATIC_REQUIRE(sizeof(DerivationRecord) == 16);
    STATIC_REQUIRE(sizeof(GroundAction) == 20);
    STATIC_REQUIRE(sizeof(Substitution) == 68);
    STATIC_REQUIRE(sizeof(DisclosureTransition) == 48);
}

TEST_CASE("hdf: literal parser", "[hdf]")
{
    ParsedLiteral l;
    std::string error;
    const std::string_view escaped = R"J(HasImport(x, "Virtual\"Alloc"))J"; // (MSVC: no raw strings inside macro arguments)
    REQUIRE(ParseLiteral(escaped, l, error));
    REQUIRE(l.name == "HasImport");
    REQUIRE(l.terms.size() == 2);
    REQUIRE(l.terms[0].kind == ParsedTerm::Kind::Variable);
    REQUIRE(l.terms[1].kind == ParsedTerm::Kind::String);
    REQUIRE(l.terms[1].text == "Virtual\"Alloc");
    REQUIRE(ParseLiteral("HasMaliciousness(x, 0.75)", l, error));
    REQUIRE(l.terms[1].kind == ParsedTerm::Kind::Number);
    REQUIRE(l.terms[1].realSyntax);
    REQUIRE(ParseLiteral(" P ( x ,-12, true , 1e-3 ) ", l, error));
    REQUIRE(l.terms.size() == 4);
    REQUIRE(l.terms[1].text == "-12");
    REQUIRE_FALSE(l.terms[1].realSyntax);
    REQUIRE(l.terms[2].kind == ParsedTerm::Kind::Bool);
    REQUIRE(l.terms[3].realSyntax);
    REQUIRE(ParseLiteral("Nullary", l, error));
    REQUIRE(l.terms.empty());
    REQUIRE(ParseLiteral("Nullary()", l, error));
    REQUIRE_FALSE(ParseLiteral("P(x", l, error));
    REQUIRE_FALSE(ParseLiteral("P(x) extra", l, error));
    REQUIRE_FALSE(ParseLiteral("P(\"unterminated)", l, error));
    REQUIRE_FALSE(ParseLiteral("1P(x)", l, error));
    REQUIRE_FALSE(ParseLiteral("P(x,,y)", l, error));
    REQUIRE_FALSE(ParseLiteral("P(a,b,c,d,e,f,g,h,i)", l, error)); // > MAX_ARITY
}

TEST_CASE("hdf: signature built-ins, completion predicates and denotations", "[hdf]")
{
    Fixture f;
    const auto& sig = f.spec->signature;
    REQUIRE(sig.predicates.Get(sig.extractedFrom).isBuiltin);
    REQUIRE(sig.actions.Get(sig.reanalyzeSelection).repeatable);
    const auto unpack = f.A("Unpack");
    const auto done   = sig.actions.Get(unpack).donePredicate;
    REQUIRE(done != INVALID_PREDICATE_ID);
    REQUIRE(sig.predicates.Get(done).name == "Done_Unpack");
    REQUIRE(sig.predicates.Get(done).completionOf == unpack);
    REQUIRE(sig.actions.Get(f.A("Rescan")).donePredicate == INVALID_PREDICATE_ID); // repeatable: no Done_a
    REQUIRE(sig.predicates.Get(f.P("HasMaliciousness")).isVerdict);
    // built-in action rule HasContent(x) ||- <ReanalyzeSelection>(x)
    bool found = false;
    for (const auto& r : f.spec->specification.actionRules)
        found |= r.head.action == sig.reanalyzeSelection;
    REQUIRE(found);

    DenotationTemplate den;
    std::string error;
    std::vector<Argument> arity{ { "x", sig.subjectSort }, { "n", sig.intSort } };
    REQUIRE(den.Compile("{x} has {{literal}} {n}", arity, error));
    REQUIRE_FALSE(den.Compile("{y}", arity, error));
    REQUIRE_FALSE(den.Compile("{x", arity, error));
}

// ---------------------------------------------------------------------------------------------------------------------
// loader validation (each error class of the specification)
// ---------------------------------------------------------------------------------------------------------------------

namespace
{
Diagnostics LoadWith(std::string_view json)
{
    Diagnostics d;
    auto spec = LoadSpecificationText(json, d);
    return d;
}
std::string WithRule(std::string_view rule, std::string_view section = "assertion_rules")
{
    return std::string(R"J({ "predicates": [
        { "name": "IsPE", "arity": [ { "name": "x", "sort": "Subject" } ] },
        { "name": "HasImport", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "api", "sort": "String" } ] },
        { "name": "HasCount", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "n", "sort": "Int" } ] },
        { "name": "Flag" },
        { "name": "Score", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "s", "sort": "Real" } ] } ],
      "actions": [ { "name": "Check", "arity": [ { "name": "x", "sort": "Subject" } ] } ],
      ")J") +
           std::string(section) + R"J(": [ )J" + std::string(rule) + " ] }";
}
// the verdict predicates V and W, the non-verdict predicate N (all Subject x Real) and the given interpretation body
std::string Interp(std::string_view body)
{
    return std::string(R"J({ "predicates": [
        { "name": "V", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "s", "sort": "Real" } ] },
        { "name": "W", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "s", "sort": "Real" } ] },
        { "name": "N", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "s", "sort": "Real" } ] } ],
      "verdicts": [ "V", "W" ], "interpretation": { )J") +
           std::string(body) + " } }";
}
} // namespace

TEST_CASE("hdf: loader validation", "[hdf]")
{
    using S = Diagnostic::Severity;
    // (MSVC does not accept raw string literals inside macro arguments: the cases are data)
    struct Case {
        std::string json;
        std::string_view fragment; // expected in an error (empty: the document must load without errors)
    };
    const std::vector<Case> cases = {
        { "{ not json", "not a valid JSON" },
        { "[]", "must be a JSON object" },
        { std::string(CORE_SPEC), "" },
        // unknown sort
        { R"J({ "predicates": [ { "name": "P", "arity": [ { "name": "x", "sort": "Nope" } ] } ] })J", "unknown sort" },
        // unknown predicate in a rule
        { WithRule(R"J({ "name": "R", "body": [ "Missing(x)" ], "head": "IsPE(x)" })J"), "unknown predicate" },
        // arity mismatch
        { WithRule(R"J({ "name": "R", "body": [ "IsPE(x, y)" ], "head": "Flag" })J"), "expects 1 argument" },
        // ill-sorted terms: string at an Int position, number at a String position, real at an Int position
        { WithRule(R"J({ "name": "R", "body": [ "HasCount(x, \"three\")" ], "head": "IsPE(x)" })J"), "ill-sorted" },
        { WithRule(R"J({ "name": "R", "body": [ "HasImport(x, 3)" ], "head": "IsPE(x)" })J"), "ill-sorted" },
        { WithRule(R"J({ "name": "R", "body": [ "HasCount(x, 2.5)" ], "head": "IsPE(x)" })J"), "ill-sorted" },
        // a variable used with two sorts
        { WithRule(R"J({ "name": "R", "body": [ "HasImport(x, n)", "HasCount(x, n)" ], "head": "IsPE(x)" })J"), "two sorts" },
        // unsafe rules: a head variable that is not in the body
        { WithRule(R"J({ "name": "R", "body": [ "IsPE(x)" ], "head": "HasImport(x, y)" })J"), "unsafe rule" },
        { WithRule(R"J({ "name": "R", "body": [ "Flag" ], "head": "Check(y)" })J", "action_rules"), "unsafe rule" },
        // empty body => the head must be ground
        { WithRule(R"J({ "name": "R", "body": [], "head": "IsPE(x)" })J"), "unsafe rule" },
        { WithRule(R"J({ "name": "R", "body": [], "head": "Flag" })J"), "" },
        // subjects can not be constants in rules
        { WithRule(R"J({ "name": "R", "body": [ "IsPE(\"s0\")" ], "head": "Flag" })J"), "ill-sorted" },
        // an action in a body, a predicate as an action head, an action as an assertion head
        { WithRule(R"J({ "name": "R", "body": [ "Check(x)" ], "head": "IsPE(x)" })J"), "used in a rule body" },
        { WithRule(R"J({ "name": "R", "body": [ "IsPE(x)" ], "head": "IsPE(x)" })J", "action_rules"), "as head" },
        { WithRule(R"J({ "name": "R", "body": [ "IsPE(x)" ], "head": "Check(x)" })J"), "as head" },
        // built-in and completion heads are reserved to the engine
        { WithRule(R"J({ "name": "R", "body": [ "IsPE(x)" ], "head": "Done_Check(x)" })J"), "reserved" },
        { WithRule(R"J({ "name": "R", "body": [ "IsPE(x)" ], "head": "HasContent(x)" })J"), "reserved" },
        // duplicate names
        { WithRule(R"J({ "name": "R", "body": [ "IsPE(x)" ], "head": "Flag" }, { "name": "R", "body": [ "IsPE(x)" ], "head": "Flag" })J"), "duplicate rule" },
        { R"J({ "predicates": [ { "name": "P" }, { "name": "P" } ] })J", "duplicate predicate" },
        { R"J({ "actions": [ { "name": "A" }, { "name": "A" } ] })J", "duplicate action" },
        { R"J({ "sorts": [ { "name": "D", "kind": "String" }, { "name": "D", "kind": "Int" } ] })J", "duplicate sort" },
        { R"J({ "predicates": [ { "name": "Bad Name" } ] })J", "not an identifier" },
        // Done_a keeps the arity of a (the unique completion assertion of a non-repeatable action)
        { R"J({ "actions": [ { "name": "A", "arity": [ { "name": "x", "sort": "Subject" } ] } ],
               "predicates": [ { "name": "Done_A", "arity": [ { "name": "x", "sort": "Int" } ] } ] })J",
          "must be declared as" },
        { R"J({ "actions": [ { "name": "A", "arity": [ { "name": "x", "sort": "Subject" } ] } ],
               "predicates": [ { "name": "Done_A", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} done" } ] })J",
          "" },
        // built-in action with a different arity
        { R"J({ "actions": [ { "name": "ReanalyzeSelection", "arity": [ { "name": "x", "sort": "Int" } ], "repeatable": true } ] })J", "built-in action" },
        // verdict predicates have the arity Subject x Real
        { R"J({ "predicates": [ { "name": "W", "arity": [ { "name": "x", "sort": "Subject" } ] } ], "verdicts": [ "W" ] })J", "Subject x Real" },
        { R"J({ "verdicts": [ "Missing" ] })J", "unknown verdict predicate" },
        // Omega = Omega_c u { Inconclusive }: the specification declares only the conclusive labels
        { R"J({ "interpretation": { "outcomes": [ "Malicious", "Benign" ] } })J", "" },
        { Interp(R"J("outcomes": [ "M", "Inconclusive" ])J"), "cannot be declared" },
        { Interp(R"J("outcomes": [ "M", "inconclusive" ])J"), "cannot be declared" },
        { Interp(R"J("outcomes": [ "M", "M" ])J"), "duplicate outcome" },
        { Interp(R"J("outcomes": [ ])J"), "non-empty array" },
        { Interp(R"J("outcomes": [ "M" ], "fallback": "Inconclusive")J"), "removed: Inconclusive is the fallback" },
        { Interp(R"J("outcomes": [ "M" ], "verdicts": [ ])J"), "removed: use" },
        { Interp(R"J("outcomes": [ "M" ], "inconclusive_alias": "Unknown")J"), "" },
        { Interp(R"J("outcomes": [ "M" ], "inconclusive_alias": "m")J"), "is a conclusive outcome" },
        { Interp(R"J("outcomes": [ "M" ], "inconclusive_alias": "")J"), "non-empty string" },
        // label conditions
        { Interp(R"J("outcomes": [ "M", "B" ], "labels": [ { "outcome": "M", "propagate": true, "clauses": [ { "present": "V", "op": ">=", "value": 0.7 },
                     { "absent": "W", "op": ">=", "value": 0.7 } ] }, { "outcome": "B", "clauses": [ { "present": "W", "op": ">", "value": 0.5 } ] } ],
                     "combination": [ { "predicate": "V", "aggregate": "noisy_or" } ], "aggregation": "strict")J"),
          "" },
        { Interp(R"J("outcomes": [ "M" ], "labels": [ { "outcome": "M", "clauses": [ { "present": "V", "absent": "W", "op": ">=", "value": 0.7 } ] } ])J"),
          "exactly one of" },
        { Interp(R"J("outcomes": [ "M" ], "labels": [ { "outcome": "M", "clauses": [ { "op": ">=", "value": 0.7 } ] } ])J"), "exactly one of" },
        { Interp(R"J("outcomes": [ "M" ], "labels": [ { "outcome": "M", "clauses": [ { "present": "N", "op": ">=", "value": 0.7 } ] } ])J"),
          "not a verdict predicate" },
        { Interp(R"J("outcomes": [ "M" ], "labels": [ { "outcome": "M", "clauses": [ { "present": "V", "op": "==", "value": 0.7 } ] } ])J"),
          "unknown operator" },
        { Interp(R"J("outcomes": [ "M" ], "labels": [ { "outcome": "M", "clauses": [ { "present": "V", "op": ">=", "value": "high" } ] } ])J"),
          "must be a number" },
        { Interp(R"J("outcomes": [ "M" ], "labels": [ { "outcome": "M", "clauses": [ ] } ])J"), "non-empty array of clauses" },
        { Interp(R"J("outcomes": [ "M" ], "labels": [ { "outcome": "M", "propagate": "yes", "clauses": [ { "present": "V", "op": ">=", "value": 1 } ] } ])J"),
          "must be a boolean" },
        { Interp(R"J("outcomes": [ "M" ], "labels": [ { "outcome": "M", "clauses": [ { "present": "V", "op": ">=", "value": 0.7 } ] },
                                                       { "outcome": "M", "clauses": [ { "present": "W", "op": ">=", "value": 0.7 } ] } ])J"),
          "two conditions" },
        { Interp(R"J("outcomes": [ "M" ], "labels": [ { "outcome": "Inconclusive", "clauses": [ { "present": "V", "op": ">=", "value": 0.7 } ] } ])J"),
          "Inconclusive has no condition" },
        { Interp(R"J("outcomes": [ "M" ], "labels": [ { "outcome": "X", "clauses": [ { "present": "V", "op": ">=", "value": 0.7 } ] } ])J"),
          "unknown outcome" },
        { Interp(R"J("outcomes": [ "M" ], "aggregation": "lenient")J"), "unknown aggregation" },
        { Interp(
                R"J("outcomes": [ "M" ], "labels": [ { "outcome": "M", "settle": "eventually", "clauses": [ { "present": "V", "op": ">=", "value": 0.7 } ] } ])J"),
          "unknown settle mode" },
        { Interp(
                R"J("outcomes": [ "M", "B" ], "labels": [ { "outcome": "M", "settle": "immediate", "clauses": [ { "present": "V", "op": ">=", "value": 0.7 } ] },
                     { "outcome": "B", "settle": "exhaustion", "clauses": [ { "present": "W", "op": ">=", "value": 0.7 } ] } ])J"),
          "" },
        // score combination
        { Interp(R"J("outcomes": [ "M" ], "combination": [ { "predicate": "V", "aggregate": "median" } ])J"), "unknown aggregate" },
        { Interp(R"J("outcomes": [ "M" ], "combination": [ { "predicate": "N", "aggregate": "max" } ])J"), "not a verdict predicate" },
        { Interp(R"J("outcomes": [ "M" ], "combination": [ { "predicate": "V", "aggregate": "max" }, { "predicate": "V", "aggregate": "min" } ])J"),
          "configured twice" },
        // wrong types are errors
        { R"J({ "predicates": { } })J", "must be an array" },
        { R"J({ "stopping": { "max_steps": -3 } })J", "non-negative" },
        // stopping policy
        { R"J({ "stopping": { "on_verdict": true } })J", "removed: use stopping.policy" },
        { R"J({ "stopping": { "policy": "eager" } })J", "unknown stopping policy" },
        { R"J({ "stopping": { "policy": "exhaustive", "max_steps": 5 } })J", "" },
    };
    for (const auto& c : cases) {
        Diagnostics d;
        LoadSpecificationText(c.json, d);
        INFO(c.json << "\n" << d.ToText());
        if (c.fragment.empty())
            CHECK_FALSE(d.HasErrors());
        else
            CHECK(d.Contains(c.fragment, S::Error));
    }

    // a conclusive outcome without a condition is never produced; a condition without a presence clause holds vacuously
    const auto unconditioned =
          LoadWith(Interp(R"J("outcomes": [ "M", "B" ], "labels": [ { "outcome": "M", "clauses": [ { "present": "V", "op": ">=", "value": 0.7 } ] } ])J"));
    REQUIRE(unconditioned.Contains("never produced", S::Warning));
    const auto vacuous =
          LoadWith(Interp(R"J("outcomes": [ "M" ], "labels": [ { "outcome": "M", "clauses": [ { "absent": "V", "op": ">=", "value": 0.7 } ] } ])J"));
    REQUIRE_FALSE(vacuous.HasErrors());
    REQUIRE(vacuous.Contains("no presence clause", S::Warning));

    // unknown keys are warnings
    const std::string unknownKeys = R"J({ "colour": 1, "predicates": [ { "name": "P", "comment": "x" } ] })J";
    auto d                        = LoadWith(unknownKeys);
    REQUIRE_FALSE(d.HasErrors());
    REQUIRE(d.Contains("unknown key", S::Warning));
    // generators are required by the tooling
    Diagnostics strict;
    LoaderOptions options;
    options.requireGenerators = true;
    LoadSpecificationText(R"J({ "predicates": [ { "name": "P" } ] })J", strict, options);
    REQUIRE(strict.Contains("generator", S::Error));
    // a rejected rule leaves the arenas untouched (the following rule still compiles)
    Diagnostics mixed;
    const auto rules = WithRule(R"J({ "name": "Bad", "body": [ "IsPE(x)", "HasCount(x, \"a\")" ], "head": "Flag" },
                                   { "name": "Good", "body": [ "IsPE(x)" ], "head": "HasCount(x, 7)" })J");
    auto spec        = LoadSpecificationText(rules, mixed);
    REQUIRE(mixed.ErrorCount() == 1);
    REQUIRE(spec->specification.assertionRules.size() == 1);
    REQUIRE(spec->specification.FormatRule(spec->specification.assertionRules[0], spec->signature, spec->pool) == "IsPE(x) |- HasCount(x, 7)");
}

// ---------------------------------------------------------------------------------------------------------------------
// Gamma, joins, closure
// ---------------------------------------------------------------------------------------------------------------------

TEST_CASE("hdf: assertion base set semantics and hash collisions", "[hdf]")
{
    for (const bool colliding : { false, true }) {
        AssertionBase gamma  = colliding ? AssertionBase(&CollidingHash) : AssertionBase();
        const ConstantId a[] = { 1, 2 }, b[] = { 2, 1 }, c[] = { 1 };
        auto r1 = gamma.Insert(5, a);
        auto r2 = gamma.Insert(5, b);
        auto r3 = gamma.Insert(6, a);
        auto r4 = gamma.Insert(5, c);
        auto r5 = gamma.Insert(5, a); // duplicate
        REQUIRE(r1.inserted);
        REQUIRE(r2.inserted);
        REQUIRE(r3.inserted);
        REQUIRE(r4.inserted);
        REQUIRE_FALSE(r5.inserted);
        REQUIRE(r5.id == r1.id);
        REQUIRE(gamma.Size() == 4);
        REQUIRE(gamma.Contains(5, b));
        REQUIRE_FALSE(gamma.Contains(7, a));
        REQUIRE(gamma.WithPredicate(5).size() == 3);
        REQUIRE(gamma.WithPredicateAndFirst(5, 1).size() == 2);
        // many colliding entries (forces growth of the open-addressing table)
        for (uint32 i = 0; i < 300; i++) {
            const ConstantId v[] = { i, i + 1 };
            REQUIRE(gamma.Insert(9, v).inserted);
        }
        for (uint32 i = 0; i < 300; i++) {
            const ConstantId v[] = { i, i + 1 };
            REQUIRE_FALSE(gamma.Insert(9, v).inserted);
            REQUIRE(gamma.Contains(9, v));
        }
        REQUIRE(gamma.Size() == 304);
    }
}

TEST_CASE("hdf: sort checking at disclosure", "[hdf]")
{
    Fixture f;
    auto& s       = f.NewSession();
    const auto x  = s.BeginRoot("sample.exe", true);
    auto& other   = f.NewSession();
    const auto x2 = other.BeginRoot("other.bin", true);
    std::string error;
    REQUIRE(s.Disclose(f.P("HasSection"), { Subject{ x }, ".text", 4096 }, {}, &error));
    REQUIRE(s.Disclose(f.P("HasSection"), { Subject{ x }, ".data", uint32(512) }, {}, &error));
    REQUIRE_FALSE(s.Disclose(f.P("HasSection"), { Subject{ x }, ".text", "4096" }, {}, &error)); // string at Int
    REQUIRE_FALSE(s.Disclose(f.P("HasSection"), { Subject{ x }, 7, 4096 }, {}, &error));         // Int at String
    REQUIRE_FALSE(s.Disclose(f.P("HasSection"), { Subject{ x }, ".text", uint64(0xFFFFFFFFFFFFFFFFull) }, {}, &error));
    REQUIRE_FALSE(s.Disclose(f.P("HasSection"), { Subject{ x }, ".text" }, {}, &error)); // arity
    REQUIRE_FALSE(s.Disclose(f.P("HasMaliciousness"), { Subject{ x }, std::numeric_limits<double>::quiet_NaN() }, {}, &error));
    REQUIRE_FALSE(s.Disclose(f.P("IsPE"), { Subject{ x2 } }, {}, &error)); // subject of another session
    REQUIRE_FALSE(s.Disclose(f.P("IsPE"), { Subject{ 999999 } }, {}, &error));
    REQUIRE_FALSE(s.Disclose(f.P("IsPE"), { "x" }, {}, &error));
    REQUIRE_FALSE(s.Disclose(f.spec->signature.extractedFrom, { Subject{ x }, Subject{ x } }, {}, &error)); // reserved
    REQUIRE_FALSE(s.Disclose(INVALID_PREDICATE_ID, { Subject{ x } }, {}, &error));
    REQUIRE(s.Disclose(f.P("ContactsDomain"), { Subject{ x }, "c2.example" }, "seen in strings", &error));
    s.EndInitialExtraction();
    // the Domain-sorted constant differs from the String-sorted one
    REQUIRE(
          f.spec->pool.FindString(f.spec->signature.sorts.Find("Domain"), "c2.example") != f.spec->pool.FindString(f.spec->signature.stringSort, "c2.example"));
    // expl(gamma) side table
    const auto list = s.Gamma().WithPredicate(f.P("ContactsDomain"));
    REQUIRE(list.size() == 1);
    REQUIRE(f.spec->pool.Strings().Get(s.Gamma().Explanation(list[0])) == "seen in strings");
}

TEST_CASE("hdf: join with shared variables across subjects", "[hdf]")
{
    // ExtractedFrom(y, x), IsPE(y) |- ContainsExecutable(x)
    Fixture f;
    auto& s       = f.NewSession();
    const auto x  = s.BeginRoot("archive.zip", true);
    const auto y1 = s.CreateSubject("a.txt", x, true, false);
    const auto y2 = s.CreateSubject("b.exe", x, true, false);
    const auto z  = s.CreateSubject("inner.zip", y1, true, false);
    REQUIRE(s.Disclose(f.P("IsArchive"), { Subject{ x } }));
    REQUIRE(s.Disclose(f.P("IsPE"), { Subject{ y2 } }));
    s.EndInitialExtraction();
    const ConstantId cx = s.SubjectConstant(x), cy1 = s.SubjectConstant(y1), cz = s.SubjectConstant(z);
    const auto contains = f.P("ContainsExecutable");
    REQUIRE(s.Gamma().Contains(contains, std::span<const ConstantId>(&cx, 1)));
    REQUIRE_FALSE(s.Gamma().Contains(contains, std::span<const ConstantId>(&cy1, 1)));
    REQUIRE_FALSE(s.Gamma().Contains(contains, std::span<const ConstantId>(&cz, 1)));
    // the derivation: rule Contains with premises ExtractedFrom(b.exe, archive.zip) and IsPE(b.exe)
    const auto id      = s.Gamma().Find(contains, std::span<const ConstantId>(&cx, 1));
    const auto& record = s.Derivations().Get(id);
    REQUIRE(record.kind == DerivationKind::Rule);
    REQUIRE(f.spec->specification.assertionRules[record.ruleOrAction].name == "Contains");
    const auto premises = s.Derivations().Premises(record);
    REQUIRE(premises.size() == 2);
    REQUIRE(s.Gamma().Predicate(premises[0]) == f.spec->signature.extractedFrom);
    REQUIRE(s.Gamma().Predicate(premises[1]) == f.P("IsPE"));
    REQUIRE(Denotation::Assertion(s, id) == "archive.zip contains an executable");
}

TEST_CASE("hdf: closure equals the naive fixpoint (random rule sets), idempotent, monotone", "[hdf]")
{
    std::mt19937 rng(20261013);
    for (int round = 0; round < 60; round++) {
        auto spec = std::make_unique<LoadedSpecification>();
        auto& sig = spec->signature;
        std::string error;
        const uint32 predicateCount = 6;
        std::vector<PredicateId> preds;
        for (uint32 p = 0; p < predicateCount; p++) {
            const bool unary              = p % 3 == 2;
            const ArgumentDeclaration a[] = { { "a", "Int" }, { "b", "Int" } };
            preds.push_back(*sig.AddPredicate("P" + std::to_string(p), std::span<const ArgumentDeclaration>(a, unary ? 1 : 2), "", error));
        }
        const char* vars[]     = { "x", "y", "z" };
        const uint32 ruleCount = 1 + rng() % 6;
        for (uint32 r = 0; r < ruleCount; r++) {
            std::vector<ParsedLiteral> body;
            std::set<std::string> bodyVars;
            const uint32 len = 1 + rng() % 3;
            for (uint32 l = 0; l < len; l++) {
                ParsedLiteral lit;
                const uint32 p     = rng() % predicateCount;
                lit.name           = "P" + std::to_string(p);
                const uint32 arity = sig.predicates.Get(preds[p]).Arity();
                for (uint32 i = 0; i < arity; i++) {
                    ParsedTerm t;
                    if (rng() % 5 == 0) {
                        t.kind = ParsedTerm::Kind::Number;
                        t.text = std::to_string(rng() % 4);
                    } else {
                        t.kind = ParsedTerm::Kind::Variable;
                        t.text = vars[rng() % 3];
                        bodyVars.insert(t.text);
                    }
                    lit.terms.push_back(t);
                }
                body.push_back(lit);
            }
            if (bodyVars.empty())
                continue;
            ParsedLiteral head;
            const uint32 hp = rng() % predicateCount;
            head.name       = "P" + std::to_string(hp);
            std::vector<std::string> vs(bodyVars.begin(), bodyVars.end());
            for (uint32 i = 0; i < sig.predicates.Get(preds[hp]).Arity(); i++)
                head.terms.push_back({ ParsedTerm::Kind::Variable, false, vs[rng() % vs.size()] });
            REQUIRE(spec->specification.AddAssertionRule("R" + std::to_string(r), body, head, "", sig, spec->pool, error));
        }
        spec->specification.Compile(sig);

        // random facts over the constants 0..7
        std::vector<std::pair<PredicateId, std::vector<ConstantId>>> facts;
        const uint32 factCount = 10 + rng() % 190;
        for (uint32 i = 0; i < factCount; i++) {
            const uint32 p = rng() % predicateCount;
            std::vector<ConstantId> args;
            for (uint32 a = 0; a < sig.predicates.Get(preds[p]).Arity(); a++)
                args.push_back(*spec->pool.InternInt(sig.intSort, rng() % 8));
            facts.emplace_back(preds[p], args);
        }
        AssertionBase semi, naive, subset;
        DerivationIndex dt, dtSubset;
        for (size_t i = 0; i < facts.size(); i++) {
            auto r = semi.Insert(facts[i].first, facts[i].second);
            if (r.inserted)
                dt.Record(r.id, DerivationKind::InitialExtraction, 0, 0, 0, 0);
            naive.Insert(facts[i].first, facts[i].second);
            if (i % 2 == 0) {
                auto rs = subset.Insert(facts[i].first, facts[i].second);
                if (rs.inserted)
                    dtSubset.Record(rs.id, DerivationKind::InitialExtraction, 0, 0, 0, 0);
            }
        }
        auto res = AssertionEntailment::Close(semi, spec->specification, 0, dt, 1, DEFAULT_MAX_DERIVED, true);
        REQUIRE_FALSE(res.limitReached);
        AssertionEntailment::CloseNaive(naive, spec->specification, DEFAULT_MAX_DERIVED);
        REQUIRE(AsSet(semi) == AsSet(naive));
        REQUIRE(dt.Size() == semi.Size());
        for (AssertionId a = 0; a < semi.Size(); a++)
            for (auto premise : dt.Premises(dt.Get(a)))
                REQUIRE(premise < a);
        // idempotent: Cl_R(Cl_R(G)) = Cl_R(G)
        const auto before = semi.Size();
        REQUIRE(AssertionEntailment::Close(semi, spec->specification, 0, dt, 2, DEFAULT_MAX_DERIVED, true).derived == 0);
        REQUIRE(semi.Size() == before);
        // monotone: G' subset G => Cl_R(G') subset Cl_R(G)
        AssertionEntailment::Close(subset, spec->specification, 0, dtSubset, 1, DEFAULT_MAX_DERIVED, true);
        const auto big = AsSet(semi);
        for (const auto& row : AsSet(subset))
            REQUIRE(big.contains(row));
        // incremental closure (fact by fact) reaches the same fixpoint
        AssertionBase incremental;
        DerivationIndex dtIncremental;
        for (const auto& fact : facts) {
            const auto begin = incremental.Size();
            auto r           = incremental.Insert(fact.first, fact.second);
            if (r.inserted) {
                dtIncremental.Record(r.id, DerivationKind::InitialExtraction, 0, 0, 0, 0);
                AssertionEntailment::Close(incremental, spec->specification, begin, dtIncremental, 1, DEFAULT_MAX_DERIVED, false);
            }
        }
        REQUIRE(AsSet(incremental) == big);
    }
}

TEST_CASE("hdf: MAX_DERIVED_PER_STEP guard", "[hdf]")
{
    // P(x, y), P(y, z) |- P(x, z) over a chain derives O(n^2) facts
    auto spec = std::make_unique<LoadedSpecification>();
    std::string error;
    const ArgumentDeclaration a[] = { { "a", "Int" }, { "b", "Int" } };
    const auto p                  = *spec->signature.AddPredicate("P", a, "", error);
    REQUIRE(spec->specification.AddAssertionRule("T", { "P(x, y)", "P(y, z)" }, "P(x, z)", spec->signature, spec->pool, error));
    spec->specification.Compile(spec->signature);
    AssertionBase gamma;
    DerivationIndex dt;
    for (int i = 0; i < 100; i++) {
        const ConstantId args[] = { *spec->pool.InternInt(spec->signature.intSort, i), *spec->pool.InternInt(spec->signature.intSort, i + 1) };
        dt.Record(gamma.Insert(p, args).id, DerivationKind::InitialExtraction, 0, 0, 0, 0);
    }
    const auto capped = AssertionEntailment::Close(gamma, spec->specification, 0, dt, 1, 500, false);
    REQUIRE(capped.limitReached);
    REQUIRE(capped.derived <= 500);
    // the capped closure is sound: continuing reaches the full transitive closure (100 * 101 / 2 pairs)
    const auto rest = AssertionEntailment::Close(gamma, spec->specification, 0, dt, 2, DEFAULT_MAX_DERIVED, false);
    REQUIRE_FALSE(rest.limitReached);
    REQUIRE(gamma.Size() == 5050);
}

// ---------------------------------------------------------------------------------------------------------------------
// actions and transitions
// ---------------------------------------------------------------------------------------------------------------------

TEST_CASE("hdf: Enabled, Completed, Selectable and Done only on success", "[hdf]")
{
    Fixture f;
    ActionStatus nextStatus = ActionStatus::Failed;
    LambdaExecutor unpack, rescan;
    uint32 unpackCalls = 0;
    unpack.fn          = [&](const GroundActionView& view, const ActionInput*, DisclosureSink& out) {
        unpackCalls++;
        REQUIRE(view.name == "Unpack");
        REQUIRE(view.SubjectArg(0) == out.Self());
        if (nextStatus == ActionStatus::Success) {
            const auto child = out.CreateSubject("payload.exe", out.Self());
            REQUIRE(child.IsValid());
            REQUIRE(out.Assert(f.P("IsPE"), { child }));
        }
        return nextStatus;
    };
    rescan.fn                  = [&](const GroundActionView&, const ActionInput*, DisclosureSink&) { return ActionStatus::Success; };
    f.executors[f.A("Unpack")] = &unpack;
    f.executors[f.A("Rescan")] = &rescan;

    auto& s      = f.NewSession();
    const auto x = s.BeginRoot("a.zip", true);
    REQUIRE(s.Disclose(f.P("IsArchive"), { Subject{ x } }));
    s.EndInitialExtraction();
    const auto beta = FindBeta(s, f.A("Unpack"), x);
    REQUIRE(beta != INVALID_GROUND_ACTION_ID);
    REQUIRE(std::find(s.Selectable().begin(), s.Selectable().end(), beta) != s.Selectable().end());
    // incremental Enabled equals the full recomputation
    REQUIRE(ActionEntailment::EnabledFull(s.Gamma(), f.spec->specification).Size() == s.Enabled().Size());

    // Failed and Cancelled: recorded, no Done_a, still selectable
    for (auto status : { ActionStatus::Failed, ActionStatus::Cancelled }) {
        nextStatus = status;
        auto r     = s.Step(beta);
        REQUIRE(r.status == StepStatus::Executed);
        REQUIRE(r.actionStatus == status);
        const auto& tr = s.Trace().transitions[r.transition];
        REQUIRE(tr.status == status);
        REQUIRE(tr.completionAssertion == INVALID_ASSERTION_ID);
        REQUIRE_FALSE(s.IsCompleted(beta));
    }
    // Success: Done_Unpack(a.zip) is added, beta leaves Selectable
    nextStatus = ActionStatus::Success;
    auto r     = s.Step(beta);
    REQUIRE(r.status == StepStatus::Executed);
    const auto& tr = s.Trace().transitions[r.transition];
    REQUIRE(tr.completionAssertion != INVALID_ASSERTION_ID);
    REQUIRE(s.Gamma().Predicate(tr.completionAssertion) == f.spec->signature.actions.Get(f.A("Unpack")).donePredicate);
    REQUIRE(s.Derivations().Get(tr.completionAssertion).kind == DerivationKind::Completion);
    REQUIRE(s.IsCompleted(beta));
    REQUIRE(std::find(s.Selectable().begin(), s.Selectable().end(), beta) == s.Selectable().end());
    REQUIRE(ActionEntailment::Completed(s.Gamma(), f.spec->signature, s.Enabled()).size() == 1);
    REQUIRE(s.Step(beta).status == StepStatus::NotSelectable);
    REQUIRE(unpackCalls == 3);
    // the child PE enabled Rescan(payload.exe) (repeatable: never completed) and ContainsExecutable(a.zip) was derived
    const SubjectId child = s.Registry().Get(x).children.at(0);
    const auto rescanBeta = FindBeta(s, f.A("Rescan"), child);
    REQUIRE(rescanBeta != INVALID_GROUND_ACTION_ID);
    for (int i = 0; i < 3; i++) {
        REQUIRE(s.Step(rescanBeta).status == StepStatus::Executed);
        REQUIRE_FALSE(s.IsCompleted(rescanBeta));
    }
    const ConstantId cx = s.SubjectConstant(x);
    REQUIRE(s.Gamma().Contains(f.P("ContainsExecutable"), std::span<const ConstantId>(&cx, 1)));
    // Selectable = Enabled \ Completed
    auto expected = ActionEntailment::Selectable(s.Gamma(), f.spec->signature, s.Enabled());
    REQUIRE(std::vector<GroundActionId>(s.Selectable().begin(), s.Selectable().end()) == expected);
    REQUIRE(ActionEntailment::EnabledFull(s.Gamma(), f.spec->specification).Size() == s.Enabled().Size());
    // no executor => the step is refused and nothing is recorded
    f.executors.erase(f.A("Rescan"));
    const auto traceSize = s.Trace().Size();
    REQUIRE(s.Step(rescanBeta).status == StepStatus::NoExecutor);
    REQUIRE(s.Trace().Size() == traceSize);
    REQUIRE(s.Step(123456).status == StepStatus::InvalidAction);
}

TEST_CASE("hdf: transition ranges, prefix inclusion and derivation records", "[hdf]")
{
    Fixture f;
    LambdaExecutor unpack;
    unpack.fn = [&](const GroundActionView&, const ActionInput*, DisclosureSink& out) {
        const auto child = out.CreateSubject("payload.exe", out.Self());
        out.Assert(f.P("IsPE"), { child });
        out.Assert(f.P("HasImport"), { child, "VirtualAlloc" });
        out.Assert(f.P("HasImport"), { child, "WriteProcessMemory" }, "import table");
        return ActionStatus::Success;
    };
    f.executors[f.A("Unpack")] = &unpack;
    auto& s                    = f.NewSession();
    const auto x               = s.BeginRoot("a.zip", true);
    s.Disclose(f.P("IsArchive"), { Subject{ x } });
    s.EndInitialExtraction();
    REQUIRE(s.HasInitialState());
    REQUIRE(s.InitialState().assertionCount == s.Gamma().Size());
    // an observation outside any scope is a transition of its own
    REQUIRE(s.Disclose(f.P("HasSection"), { Subject{ x }, ".rsrc", 10 }));
    REQUIRE(s.Trace().transitions.back().kind == TransitionKind::Observation);
    const auto stepResult = s.Step(FindBeta(s, f.A("Unpack"), x));
    REQUIRE(stepResult.status == StepStatus::Executed);

    const auto& trace = s.Trace();
    REQUIRE(trace.Size() == 3);
    REQUIRE(trace.ActionCount() == 1);
    uint32 previous = 0;
    for (uint32 t = 0; t < trace.Size(); t++) {
        const auto& tr = trace.transitions[t];
        REQUIRE(tr.fromCount == previous); // Gamma_i is the prefix left by the previous transition
        REQUIRE(tr.fromCount <= tr.disclosedBegin);
        REQUIRE(tr.disclosedBegin <= tr.disclosedEnd);
        REQUIRE(tr.disclosedEnd <= tr.toCount);
        previous = tr.toCount;
        for (AssertionId a = tr.disclosedBegin; a < tr.toCount; a++)
            REQUIRE(s.Derivations().Get(a).transition == t);
    }
    // the step: Gamma_beta holds the child's provenance + 3 disclosures; D_beta; then the derived assertions
    const auto& step = trace.transitions[2];
    REQUIRE(step.kind == TransitionKind::Action);
    REQUIRE(step.disclosedEnd - step.disclosedBegin == 6); // ExtractedFrom, HasName, HasContent, IsPE, 2x HasImport
    REQUIRE(step.completionAssertion == step.disclosedEnd);
    for (AssertionId a = step.disclosedBegin; a < step.disclosedEnd; a++) {
        const auto& record = s.Derivations().Get(a);
        REQUIRE(record.kind == DerivationKind::Action);
        REQUIRE(record.ruleOrAction == step.action);
        // the premises of an action-disclosed assertion are the enabling premises of beta (IsArchive(a.zip))
        REQUIRE(s.Derivations().Premises(record).size() == 1);
    }
    // two-level derivation tree: HasMaliciousness <- Injection <- {IsPE, HasImport, HasImport} <- IsArchive (enabling)
    const auto verdicts = s.Gamma().WithPredicate(f.P("HasMaliciousness"));
    REQUIRE(verdicts.size() == 1);
    const auto tree = DerivationTree::Build(s.Derivations(), verdicts[0]);
    REQUIRE_FALSE(tree.truncated);
    REQUIRE(tree.nodes.size() == 1 + 1 + 3 + 3);
    REQUIRE(s.Gamma().Predicate(tree.nodes[1].assertion) == f.P("Injection"));
    REQUIRE(tree.nodes[1].depth == 1);
    REQUIRE(tree.nodes[2].depth == 2);
    REQUIRE(s.Derivations().Get(tree.nodes[2].assertion).kind == DerivationKind::Action);
    REQUIRE(tree.nodes[3].depth == 3); // IsArchive(a.zip), the enabling premise of Unpack(a.zip)
    for (const auto& node : tree.nodes)
        if (node.parent != INVALID_INDEX)
            REQUIRE(node.assertion < tree.nodes[node.parent].assertion);
    const auto truncated = DerivationTree::Build(s.Derivations(), verdicts[0], 1, 4096);
    REQUIRE(truncated.truncated);
    // Gamma_i are prefixes: every Gamma_i subset Gamma_i+1
    REQUIRE(s.StateAfter(0).assertionCount <= s.StateAfter(1).assertionCount);
    REQUIRE(s.StateAfter(1).assertionCount <= s.StateAfter(2).assertionCount);
    REQUIRE(f.transitionsSeen == 3);
}

TEST_CASE("hdf: nested scopes join the open transition", "[hdf]")
{
    Fixture f;
    LambdaExecutor unpack;
    DisclosureSession* session = nullptr;
    unpack.fn                  = [&](const GroundActionView&, const ActionInput*, DisclosureSink& out) {
        const auto child = out.CreateSubject("inner.exe", out.Self());
        REQUIRE(session->PendingSubject() == child.id); // a window opened now attaches to this subject
        // the window of the new subject runs its initial extraction inside the step (implicit CheckType)
        session->BeginInitialExtraction(child.id);
        session->Disclose(f.P("IsPE"), { child });
        session->BeginObservation(child.id, "nested");
        session->Disclose(f.P("HasImport"), { child, "VirtualAlloc" });
        session->EndObservation();
        session->EndInitialExtraction();
        return ActionStatus::Success;
    };
    f.executors[f.A("Unpack")] = &unpack;
    auto& s                    = f.NewSession();
    session                    = &s;
    const auto x               = s.BeginRoot("a.zip", true);
    s.Disclose(f.P("IsArchive"), { Subject{ x } });
    s.BeginObservation(x, "nested in initial extraction");
    s.Disclose(f.P("HasSection"), { Subject{ x }, ".text", 1 });
    s.EndObservation();
    s.EndInitialExtraction();
    REQUIRE(s.Trace().Size() == 1);
    REQUIRE(s.Step(FindBeta(s, f.A("Unpack"), x)).status == StepStatus::Executed);
    REQUIRE(s.Trace().Size() == 2);
    REQUIRE(s.PendingSubject() == INVALID_SUBJECT_ID);
    REQUIRE_FALSE(s.IsScopeOpen());
}

// ---------------------------------------------------------------------------------------------------------------------
// interpretation, explanation, stopping policy
// ---------------------------------------------------------------------------------------------------------------------

namespace
{
// Malicious and Benign overlap: a subject with both scores satisfies both conditions (I_subj = Inconclusive / Conflict)
constexpr std::string_view CONFLICT_SPEC = R"JSON({
  "predicates": [
    { "name": "HasMaliciousness", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "score", "sort": "Real" } ] },
    { "name": "HasBenignity", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "score", "sort": "Real" } ] }
  ],
  "verdicts": [ "HasMaliciousness", "HasBenignity" ],
  "interpretation": {
    "outcomes": [ "Malicious", "Benign" ],
    "labels": [
      { "outcome": "Malicious", "propagate": true, "clauses": [ { "present": "HasMaliciousness", "op": ">=", "value": 0.70 } ] },
      { "outcome": "Benign", "clauses": [ { "present": "HasBenignity", "op": ">=", "value": 0.70 } ] }
    ],
    "aggregation": "default"
  },
  "stopping": { "policy": "manual" }
})JSON";

constexpr uint8 MALICIOUS = 0;
constexpr uint8 BENIGN    = 1;

double RealArg(const DisclosureSession& s, AssertionId a)
{
    return s.Pool().AsReal(s.Gamma().Args(a)[1]);
}

bool Contains(const std::string& text, std::string_view fragment)
{
    return text.find(fragment) != std::string::npos;
}

uint32 Selectable(const DisclosureSession& s)
{
    return static_cast<uint32>(s.Selectable().size());
}
} // namespace

TEST_CASE("hdf: score combination functions", "[hdf]")
{
    const double scores[] = { 0.2, 0.5, 0.9 };
    REQUIRE(Interpretation::Aggregate(AggregateFunction::Max, scores) == 0.9);
    REQUIRE(Interpretation::Aggregate(AggregateFunction::Min, scores) == 0.2);
    REQUIRE(Interpretation::Aggregate(AggregateFunction::Mean, scores) == Catch::Approx(1.6 / 3));
    REQUIRE(Interpretation::Aggregate(AggregateFunction::NoisyOr, scores) == Catch::Approx(1.0 - 0.8 * 0.5 * 0.1));
    const double clampTest[] = { 1.5, -2.0 };
    REQUIRE(Interpretation::Aggregate(AggregateFunction::NoisyOr, clampTest) == Catch::Approx(1.0));
    REQUIRE(Interpretation::Aggregate(AggregateFunction::Max, std::span<const double>()) == 0.0);
    REQUIRE(Interpretation::Compare(ComparisonOperator::GreaterEqual, 0.7, 0.7));
    REQUIRE_FALSE(Interpretation::Compare(ComparisonOperator::Greater, 0.7, 0.7));
    REQUIRE(Interpretation::Compare(ComparisonOperator::LessEqual, 0.3, 0.3));
    REQUIRE_FALSE(Interpretation::Compare(ComparisonOperator::Less, 0.3, 0.3));
    REQUIRE_FALSE(ComparisonOperatorFromName("==").has_value()); // the operator set is { >=, >, <=, < }
}

TEST_CASE("hdf: Omega = Omega_c u {Inconclusive} is built by the loader", "[hdf]")
{
    Fixture f;
    const auto& interpretation = f.spec->interpretation;
    const auto& omega          = interpretation.outcomes;
    REQUIRE(omega.labels == std::vector<std::string>{ "Malicious", "Benign", "Inconclusive" });
    REQUIRE(omega.labels.back() == "Inconclusive"); // appended by the framework
    REQUIRE(omega.inconclusiveIndex == 2);          // == |Omega_c|
    REQUIRE(omega.ConclusiveCount() == 2);
    REQUIRE(omega.IsConclusive({ MALICIOUS }));
    REQUIRE(omega.IsConclusive({ BENIGN }));
    REQUIRE_FALSE(omega.IsConclusive(omega.Inconclusive()));
    REQUIRE(omega.Label(omega.Inconclusive()) == "Inconclusive");
    REQUIRE(interpretation.labels.size() == 2);
    REQUIRE(interpretation.labels[0].outcome == MALICIOUS);
    REQUIRE(interpretation.labels[0].propagate);
    REQUIRE(interpretation.labels[0].clauses.size() == 2);
    REQUIRE(interpretation.labels[0].clauses[1].kind == ClauseKind::Absent);
    REQUIRE(interpretation.labels[0].clauses[1].predicate == f.P("HasBenignity"));
    REQUIRE(interpretation.labels[0].settle == SettleMode::Immediate);
    REQUIRE_FALSE(interpretation.labels[1].propagate);
    REQUIRE(interpretation.labels[1].settle == SettleMode::Exhaustion);
    REQUIRE(interpretation.labels[1].clauses[1].op == ComparisonOperator::Greater);
    REQUIRE(interpretation.aggregation == SubjectAggregationKind::Default);
    REQUIRE(interpretation.Combination(f.P("HasMaliciousness")) == AggregateFunction::Max); // the default combination
    REQUIRE(f.spec->stopping.kind == StoppingPolicyKind::Conclusive);

    // the alias only renames Inconclusive in the output
    std::string json(CORE_SPEC);
    const std::string anchor = R"J("outcomes": [ "Malicious", "Benign" ],)J";
    const auto at            = json.find(anchor);
    REQUIRE(at != std::string::npos);
    json.insert(at + anchor.size(), R"J( "inconclusive_alias": "Unknown",)J");
    Fixture aliased(json);
    const auto& omega2 = aliased.spec->interpretation.outcomes;
    REQUIRE(omega2.Label(omega2.Inconclusive()) == "Unknown");
    REQUIRE_FALSE(omega2.IsConclusive(omega2.Inconclusive()));
    REQUIRE(omega2.Find("Inconclusive") == std::optional<uint8>(2));
    REQUIRE_FALSE(omega2.Find("Unknown").has_value());
    auto& s = aliased.NewSession(ManualPolicy());
    s.BeginRoot("x", true);
    s.EndInitialExtraction();
    REQUIRE(ExplanationFormatter::DecisionSummary(s.LastDecision(), aliased.spec->interpretation, s.Registry()) == "Unknown (no label satisfied)");

    // no interpretation section: Omega = { Inconclusive }
    Diagnostics d;
    auto bare = LoadSpecificationText(
          R"J({ "predicates": [ { "name": "V", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "s", "sort": "Real" } ] } ],
                                            "verdicts": [ "V" ] })J",
          d);
    REQUIRE(bare);
    REQUIRE(d.Contains("missing", Diagnostic::Severity::Warning));
    REQUIRE(bare->interpretation.outcomes.labels == std::vector<std::string>{ "Inconclusive" });
    REQUIRE(bare->interpretation.outcomes.inconclusiveIndex == 0);
    REQUIRE(bare->interpretation.labels.empty());
}

TEST_CASE("hdf: per-subject interpretation (clauses, exactly-one rule, reasons)", "[hdf]")
{
    Fixture f;
    const auto& interpretation = f.spec->interpretation;
    const auto mal             = f.P("HasMaliciousness");
    const auto ben             = f.P("HasBenignity");
    auto& s                    = f.NewSession(ManualPolicy());
    const auto root            = s.BeginRoot("root", true);
    const auto m               = s.CreateSubject("m", root, true, false);
    const auto blocked         = s.CreateSubject("blocked", root, true, false);
    const auto b               = s.CreateSubject("b", root, true, false);
    const auto benignBlocked   = s.CreateSubject("benignBlocked", root, true, false);
    const auto none            = s.CreateSubject("none", root, true, false);
    const auto two             = s.CreateSubject("two", root, true, false);
    REQUIRE(s.Disclose(mal, { Subject{ m }, 0.80 }));
    REQUIRE(s.Disclose(mal, { Subject{ blocked }, 0.80 }));
    REQUIRE(s.Disclose(ben, { Subject{ blocked }, 0.85 }));
    REQUIRE(s.Disclose(ben, { Subject{ b }, 0.85 }));
    REQUIRE(s.Disclose(ben, { Subject{ benignBlocked }, 0.85 }));
    REQUIRE(s.Disclose(mal, { Subject{ benignBlocked }, 0.35 }));
    REQUIRE(s.Disclose(mal, { Subject{ two }, 0.75 }));
    REQUIRE(s.Disclose(mal, { Subject{ two }, 0.60 }));
    s.EndInitialExtraction();
    auto subject = [&](SubjectId y) { return interpretation.InterpretSubject(s.Gamma(), f.spec->signature, f.spec->pool, y, s.SubjectConstant(y)); };

    SECTION("Malicious: the presence clause and the absence clause hold")
    {
        const auto d = subject(m);
        REQUIRE(d.outcome.index == MALICIOUS);
        REQUIRE(d.reason == InconclusiveReason::None);
        const auto* label = d.FindLabel(MALICIOUS);
        REQUIRE(label);
        REQUIRE(label->holds);
        REQUIRE(label->firstFailedClause == -1);
        REQUIRE(label->clauses[0].present);
        REQUIRE(label->clauses[0].score == 0.80);
        REQUIRE(label->clauses[0].witness != INVALID_ASSERTION_ID);
        REQUIRE_FALSE(label->clauses[1].present); // no HasBenignity(m, c): the absence clause holds
        REQUIRE(label->clauses[1].holds);
        REQUIRE_FALSE(d.FindLabel(BENIGN)->holds);
    }
    SECTION("Malicious blocked by HasBenignity 0.85: no label satisfied")
    {
        const auto d = subject(blocked);
        REQUIRE(d.outcome.index == interpretation.outcomes.inconclusiveIndex);
        REQUIRE(d.reason == InconclusiveReason::NoLabelSatisfied);
        const auto* malicious = d.FindLabel(MALICIOUS);
        REQUIRE(malicious->firstFailedClause == 1); // no HasBenignity >= 0.70
        REQUIRE(malicious->clauses[1].present);
        REQUIRE(malicious->clauses[1].score == 0.85);
        const auto* benign = d.FindLabel(BENIGN);
        REQUIRE(benign->firstFailedClause == 1); // no HasMaliciousness > 0.30
        REQUIRE(benign->clauses[1].score == 0.80);
    }
    SECTION("Benign")
    {
        const auto d = subject(b);
        REQUIRE(d.outcome.index == BENIGN);
        REQUIRE(d.FindLabel(BENIGN)->clauses[1].holds); // no HasMaliciousness at all
        REQUIRE(d.FindLabel(MALICIOUS)->firstFailedClause == 0);
    }
    SECTION("Benign blocked by HasMaliciousness 0.35")
    {
        const auto d = subject(benignBlocked);
        REQUIRE(d.reason == InconclusiveReason::NoLabelSatisfied);
        const auto* benign = d.FindLabel(BENIGN);
        REQUIRE(benign->firstFailedClause == 1);
        REQUIRE(benign->clauses[1].present);
        REQUIRE(benign->clauses[1].score == 0.35);
        REQUIRE(d.FindLabel(MALICIOUS)->firstFailedClause == 0); // 0.35 < 0.70
    }
    SECTION("no verdict assertion: the presence clauses are missing")
    {
        const auto d = subject(none);
        REQUIRE(d.reason == InconclusiveReason::NoLabelSatisfied);
        REQUIRE(d.scores.empty());
        for (const auto o : { MALICIOUS, BENIGN }) {
            const auto* label = d.FindLabel(o);
            REQUIRE(label->firstFailedClause == 0);
            REQUIRE_FALSE(label->clauses[0].present);
            REQUIRE(label->clauses[0].witness == INVALID_ASSERTION_ID);
        }
    }
    SECTION("two HasMaliciousness scores combined by max")
    {
        const auto d = subject(two);
        REQUIRE(d.outcome.index == MALICIOUS);
        const auto* score = d.FindScore(mal);
        REQUIRE(score);
        REQUIRE(score->score == 0.75);
        REQUIRE(score->count == 2);
        REQUIRE(score->aggregate == AggregateFunction::Max);
        REQUIRE(RealArg(s, score->strongest) == 0.75);
        REQUIRE(d.FindLabel(MALICIOUS)->clauses[0].witness == score->strongest);
    }
    SECTION("an invalid subject constant reads no score")
    {
        const auto d = interpretation.InterpretSubject(s.Gamma(), f.spec->signature, f.spec->pool, m, INVALID_CONSTANT_ID);
        REQUIRE(d.scores.empty());
        REQUIRE(d.reason == InconclusiveReason::NoLabelSatisfied);
    }
}

TEST_CASE("hdf: score combination is replaceable per verdict predicate", "[hdf]")
{
    std::string json(CORE_SPEC);
    const std::string anchor = R"J("outcomes": [ "Malicious", "Benign" ],)J";
    const auto at            = json.find(anchor);
    REQUIRE(at != std::string::npos);
    json.insert(at + anchor.size(), R"J( "combination": [ { "predicate": "HasMaliciousness", "aggregate": "mean" } ],)J");
    Fixture f(json);
    REQUIRE(f.spec->interpretation.Combination(f.P("HasMaliciousness")) == AggregateFunction::Mean);
    REQUIRE(f.spec->interpretation.Combination(f.P("HasBenignity")) == AggregateFunction::Max);
    auto& s      = f.NewSession(ManualPolicy());
    const auto x = s.BeginRoot("x", true);
    REQUIRE(s.Disclose(f.P("HasMaliciousness"), { Subject{ x }, 0.75 }));
    REQUIRE(s.Disclose(f.P("HasMaliciousness"), { Subject{ x }, 0.60 }));
    REQUIRE(s.Disclose(f.P("HasMaliciousness"), { Subject{ x }, 0.60 })); // set semantics: one assertion per score
    s.EndInitialExtraction();
    const auto d = f.spec->interpretation.Interpret(s.Gamma(), f.spec->signature, f.spec->pool, s.Registry(), x, Selectable(s));
    REQUIRE(d.subjects.size() == 1);
    const auto* score = d.subjects[0].FindScore(f.P("HasMaliciousness"));
    REQUIRE(score->count == 2);
    REQUIRE(score->score == Catch::Approx(0.675));
    REQUIRE(RealArg(s, score->strongest) == 0.75); // the DT still shows the strongest assertion
    // 0.675 fails ">= 0.70": Inconclusive, the first failed clause of Malicious is its presence clause
    REQUIRE_FALSE(d.conclusive);
    REQUIRE(d.reason == InconclusiveReason::NoLabelSatisfied);
    REQUIRE(d.subjects[0].FindLabel(MALICIOUS)->firstFailedClause == 0);
    REQUIRE(d.subjects[0].FindLabel(MALICIOUS)->clauses[0].present);
}

TEST_CASE("hdf: conflict between two labels of one subject", "[hdf]")
{
    Fixture f(CONFLICT_SPEC);
    auto& s      = f.NewSession(f.spec->stopping);
    const auto x = s.BeginRoot("dual.exe", true);
    REQUIRE(s.Disclose(f.P("HasMaliciousness"), { Subject{ x }, 0.80 }));
    REQUIRE(s.Disclose(f.P("HasBenignity"), { Subject{ x }, 0.90 }));
    s.EndInitialExtraction();
    const auto& d = s.LastDecision();
    REQUIRE(s.HasDecision());
    REQUIRE_FALSE(d.conclusive);
    REQUIRE(d.reason == InconclusiveReason::Conflict);
    REQUIRE(d.conflictingLabels == std::vector<uint8>{ MALICIOUS, BENIGN });
    REQUIRE(d.subjects[0].reason == InconclusiveReason::Conflict);
    REQUIRE_FALSE(s.IsFinished()); // a conflict is not a stop reason
    REQUIRE(ExplanationFormatter::DecisionSummary(d, f.spec->interpretation, s.Registry()) == "Inconclusive (conflict: Malicious, Benign)");
    const auto md = ExplanationFormatter::ToMarkdown(Explanation::Build(s, f.spec->interpretation, x), f.spec->interpretation);
    REQUIRE(Contains(md, "reason: conflict (Malicious, Benign)"));
    REQUIRE(Contains(md, "Malicious holds for dual.exe:"));
    REQUIRE(Contains(md, "Benign holds for dual.exe:"));
    REQUIRE(Contains(md, "HasBenignity(dual.exe, .) = max{0.90} = 0.90 >= 0.70 [holds]"));
    REQUIRE(Contains(md, "core stop reason: none (in progress)"));
}

TEST_CASE("hdf: aggregation over subjects (maliciousness propagates upward, benignity never)", "[hdf]")
{
    SECTION("installer.exe (benign) extracted payload.exe (malicious) => Malicious")
    {
        Fixture f;
        auto& s            = f.NewSession(); // conclusive
        const auto install = s.BeginRoot("installer.exe", true);
        const auto payload = s.CreateSubject("payload.exe", install, true, false);
        REQUIRE(s.Disclose(f.P("HasBenignity"), { Subject{ install }, 0.85 }));
        REQUIRE(s.Disclose(f.P("HasMaliciousness"), { Subject{ payload }, 0.80 }));
        s.EndInitialExtraction();
        const auto& d = s.LastDecision();
        REQUIRE(d.conclusive);
        REQUIRE(d.outcome.index == MALICIOUS);
        REQUIRE(d.input == install);
        REQUIRE(d.deciding == payload);
        REQUIRE(d.provenancePath == std::vector<SubjectId>{ payload, install });
        REQUIRE(d.subjects.size() == 2);
        REQUIRE(d.subjects[0].subject == install);
        REQUIRE(d.subjects[0].outcome.index == BENIGN); // I_subj(installer.exe) = Benign
        REQUIRE(d.subjects[1].outcome.index == MALICIOUS);
        REQUIRE(s.IsFinished());
        REQUIRE(s.GetStopReason() == StopReason::Conclusive);
        REQUIRE(ExplanationFormatter::DecisionSummary(d, f.spec->interpretation, s.Registry()) == "Malicious (conclusive, via payload.exe)");
        const auto e = Explanation::Build(s, f.spec->interpretation, install);
        REQUIRE(e.witnesses.size() == 1);
        REQUIRE(RealArg(s, e.witnesses[0].first) == 0.80);
        const auto md = ExplanationFormatter::ToMarkdown(e, f.spec->interpretation);
        REQUIRE(Contains(md, "I_subj(installer.exe) = Benign"));
        REQUIRE(Contains(md, "I_subj(payload.exe) = Malicious, propagated to installer.exe along installer.exe -> payload.exe"));
        REQUIRE(Contains(md, "HasMaliciousness(payload.exe, .) = max{0.80} = 0.80 >= 0.70 [holds]"));
        REQUIRE(Contains(md, "no HasBenignity(payload.exe, c) with c >= 0.70 [holds: no assertion]"));
        REQUIRE(Contains(md, "## Provenance\ninstaller.exe -> payload.exe"));
    }
    SECTION("a benign child does not make an inconclusive parent benign")
    {
        Fixture f;
        auto& s           = f.NewSession(ManualPolicy());
        const auto parent = s.BeginRoot("parent.zip", true);
        const auto child  = s.CreateSubject("signed.exe", parent, true, false);
        REQUIRE(s.Disclose(f.P("HasBenignity"), { Subject{ child }, 0.85 }));
        s.EndInitialExtraction();
        const auto& interpretation = f.spec->interpretation;
        const auto d               = interpretation.Interpret(s.Gamma(), f.spec->signature, f.spec->pool, s.Registry(), parent, Selectable(s));
        REQUIRE_FALSE(d.conclusive);
        REQUIRE(d.reason == InconclusiveReason::NoLabelSatisfied); // the reason of I_subj(parent.zip)
        REQUIRE(d.deciding == parent);
        REQUIRE(d.subjects[1].outcome.index == BENIGN);
        // the child on its own is Benign
        REQUIRE(interpretation.Interpret(s.Gamma(), f.spec->signature, f.spec->pool, s.Registry(), child, Selectable(s)).outcome.index == BENIGN);
    }
    SECTION("the first malicious subject in pre-order decides")
    {
        Fixture f;
        auto& s      = f.NewSession(ManualPolicy());
        const auto x = s.BeginRoot("root", true);
        const auto a = s.CreateSubject("a", x, true, false);
        const auto b = s.CreateSubject("b", a, true, false);
        const auto c = s.CreateSubject("c", x, true, false);
        REQUIRE(s.Disclose(f.P("HasMaliciousness"), { Subject{ c }, 0.95 }));
        REQUIRE(s.Disclose(f.P("HasMaliciousness"), { Subject{ b }, 0.75 }));
        s.EndInitialExtraction();
        const auto d = f.spec->interpretation.Interpret(s.Gamma(), f.spec->signature, f.spec->pool, s.Registry(), x, Selectable(s));
        REQUIRE(d.outcome.index == MALICIOUS);
        REQUIRE(d.deciding == b); // pre-order: root, a, b, c (no priority by score or by distance)
        REQUIRE(d.provenancePath == std::vector<SubjectId>{ b, a, x });
    }
    SECTION("strict aggregation blocks Benign when a descendant is in conflict, default does not")
    {
        for (const bool strict : { false, true }) {
            std::string json(CONFLICT_SPEC);
            if (strict) {
                const auto at = json.find("\"default\"");
                REQUIRE(at != std::string::npos);
                json.replace(at, std::string("\"default\"").size(), "\"strict\"");
            }
            Fixture f(json);
            REQUIRE(f.spec->interpretation.aggregation == (strict ? SubjectAggregationKind::Strict : SubjectAggregationKind::Default));
            auto& s          = f.NewSession(ManualPolicy());
            const auto x     = s.BeginRoot("package", true);
            const auto inner = s.CreateSubject("dual.exe", x, true, false);
            REQUIRE(s.Disclose(f.P("HasBenignity"), { Subject{ x }, 0.90 }));
            REQUIRE(s.Disclose(f.P("HasMaliciousness"), { Subject{ inner }, 0.80 }));
            REQUIRE(s.Disclose(f.P("HasBenignity"), { Subject{ inner }, 0.80 }));
            s.EndInitialExtraction();
            const auto& d = s.LastDecision();
            REQUIRE(d.subjects[1].reason == InconclusiveReason::Conflict);
            if (!strict) {
                REQUIRE(d.outcome.index == BENIGN);
                REQUIRE(d.deciding == x);
                // the strict hook passed explicitly gives the strict result on the same Gamma
                const StrictSubjectAggregation strictHook;
                const auto blocked = f.spec->interpretation.Interpret(s.Gamma(), f.spec->signature, f.spec->pool, s.Registry(), x, Selectable(s), &strictHook);
                REQUIRE(blocked.reason == InconclusiveReason::Conflict);
            } else {
                REQUIRE_FALSE(d.conclusive);
                REQUIRE(d.reason == InconclusiveReason::Conflict);
                REQUIRE(d.conflictingLabels == std::vector<uint8>{ MALICIOUS, BENIGN });
                REQUIRE(d.deciding == inner);
                const auto md = ExplanationFormatter::ToMarkdown(Explanation::Build(s, f.spec->interpretation, x), f.spec->interpretation);
                REQUIRE(Contains(md, "reason: conflict (Malicious, Benign) on dual.exe (strict aggregation over subjects)"));
            }
        }
    }
    SECTION("a custom aggregation hook")
    {
        // a hook that reports Benign for X whatever the evidence (the framework keeps the invariants)
        struct AlwaysBenign : SubjectAggregationInterface {
            void Aggregate(
                  const Interpretation&, const SubjectRegistry&, SubjectId input, std::span<const SubjectDecision>, InterpretationDecision& out) const override
            {
                out.outcome  = { BENIGN };
                out.deciding = input;
            }
        } hook;
        Fixture f;
        auto& s      = f.NewSession(ManualPolicy());
        const auto x = s.BeginRoot("x", true);
        s.EndInitialExtraction();
        const auto d = f.spec->interpretation.Interpret(s.Gamma(), f.spec->signature, f.spec->pool, s.Registry(), x, Selectable(s), &hook);
        REQUIRE(d.outcome.index == BENIGN);
        REQUIRE(d.conclusive);
        REQUIRE(d.reason == InconclusiveReason::None);
        REQUIRE(d.provenancePath == std::vector<SubjectId>{ x });
    }
}

TEST_CASE("hdf: explanation of each outcome reason", "[hdf]")
{
    SECTION("conclusive: one line per clause and the DT of the witness")
    {
        Fixture f;
        auto& s      = f.NewSession();
        const auto x = s.BeginRoot("sample.exe", true);
        s.Disclose(f.P("IsPE"), { Subject{ x } });
        s.Disclose(f.P("HasImport"), { Subject{ x }, "VirtualAlloc" });
        s.Disclose(f.P("HasImport"), { Subject{ x }, "WriteProcessMemory" });
        s.EndInitialExtraction();
        REQUIRE(s.IsFinished());
        const auto e  = Explanation::Build(s, f.spec->interpretation, x);
        const auto md = ExplanationFormatter::ToMarkdown(e, f.spec->interpretation);
        REQUIRE(e.outcome == "Malicious");
        REQUIRE(e.stopReason == StopReason::Conclusive);
        REQUIRE(Contains(md, "I_subj(sample.exe) = Malicious\n"));
        REQUIRE(Contains(md, "Malicious holds for sample.exe:"));
        REQUIRE(Contains(md, "HasMaliciousness(sample.exe, .) = max{0.80} = 0.80 >= 0.70 [holds]"));
        REQUIRE(Contains(md, "no HasBenignity(sample.exe, c) with c >= 0.70 [holds: no assertion]"));
        REQUIRE_FALSE(Contains(md, "propagated"));
        REQUIRE(Contains(md, "## Verdict assertions"));
        REQUIRE(Contains(md, "Rule Verdict: Injection(x) |- HasMaliciousness(x, 0.80)"));
        REQUIRE(Contains(md, "sample.exe can inject code"));
        REQUIRE_FALSE(Contains(md, "Why: ")); // the Verdict rule has no explanation
        REQUIRE(Contains(md, "## Stop reason\nconclusive"));
        REQUIRE(e.witnesses.size() == 1);
        const auto treeText = ExplanationFormatter::DerivationTreeText(s, e.witnesses[0].second);
        REQUIRE(Contains(treeText, "rule Inject"));
        REQUIRE(Contains(treeText, "initial extraction"));
        REQUIRE(Contains(md, "## Derivation trees"));
    }
    SECTION("no label satisfied: the first failed clause of each label")
    {
        Fixture f;
        auto& s      = f.NewSession();
        const auto x = s.BeginRoot("dropper.exe", true);
        s.Disclose(f.P("HasImport"), { Subject{ x }, "URLDownloadToFileA" }); // HasMaliciousness 0.60
        s.EndInitialExtraction();
        REQUIRE_FALSE(s.IsFinished());
        const auto e  = Explanation::Build(s, f.spec->interpretation, x);
        const auto md = ExplanationFormatter::ToMarkdown(e, f.spec->interpretation);
        REQUIRE(e.outcome == "Inconclusive");
        REQUIRE(e.witnesses.empty());
        REQUIRE(Contains(md, "I_subj(dropper.exe) = Inconclusive (no label satisfied)"));
        REQUIRE(Contains(md, "reason: no label satisfied"));
        REQUIRE(Contains(md, "  Malicious: HasMaliciousness(dropper.exe, .) = max{0.60} = 0.60, not >= 0.70 [fails]"));
        REQUIRE(Contains(md, "  Benign: HasBenignity(dropper.exe, .) missing [fails]"));
        REQUIRE(Contains(md, "core stop reason: none (in progress)"));
        REQUIRE_FALSE(Contains(md, "## Verdict assertions"));
        REQUIRE(ExplanationFormatter::DecisionSummary(s.LastDecision(), f.spec->interpretation, s.Registry()) == "Inconclusive (no label satisfied)");
        s.Finish(StopReason::ManualStop);
        const auto stopped = ExplanationFormatter::ToMarkdown(Explanation::Build(s, f.spec->interpretation, x), f.spec->interpretation);
        REQUIRE(Contains(stopped, "core stop reason: manual stop"));
    }
    SECTION("Benign blocked by an absence clause")
    {
        Fixture f;
        auto& s      = f.NewSession(ManualPolicy());
        const auto x = s.BeginRoot("tool.exe", true);
        s.Disclose(f.P("HasBenignity"), { Subject{ x }, 0.85 });
        s.Disclose(f.P("HasMaliciousness"), { Subject{ x }, 0.35 });
        s.EndInitialExtraction();
        const auto md = ExplanationFormatter::ToMarkdown(Explanation::Build(s, f.spec->interpretation, x), f.spec->interpretation);
        REQUIRE(Contains(
              md, "  Benign: no HasMaliciousness(tool.exe, c) with c > 0.30 [fails: HasMaliciousness(tool.exe, .) = max{0.35} = 0.35 > 0.30 present]"));
        REQUIRE(Contains(md, "  Malicious: HasMaliciousness(tool.exe, .) = max{0.35} = 0.35, not >= 0.70 [fails]"));
    }
}

TEST_CASE("hdf: stopping policy", "[hdf]")
{
    LambdaExecutor rescan;
    std::function<void(DisclosureSink&)> onRescan = [](DisclosureSink&) {};
    rescan.fn                                     = [&](const GroundActionView&, const ActionInput*, DisclosureSink& out) {
        onRescan(out);
        return ActionStatus::Success;
    };

    SECTION("conclusive (default) stops as soon as I is conclusive: initial extraction")
    {
        Fixture f;
        auto& s      = f.NewSession();
        const auto x = s.BeginRoot("x", true);
        s.Disclose(f.P("IsPE"), { Subject{ x } });
        s.Disclose(f.P("HasImport"), { Subject{ x }, "VirtualAlloc" });
        s.Disclose(f.P("HasImport"), { Subject{ x }, "WriteProcessMemory" });
        s.EndInitialExtraction();
        REQUIRE(s.IsFinished());
        REQUIRE(s.GetStopReason() == StopReason::Conclusive);
        REQUIRE(s.Result().stopReason == StopReason::Conclusive);
        REQUIRE(s.LastDecision().conclusive);
        REQUIRE(s.Step(0).status == StepStatus::Finished);
    }
    SECTION("conclusive stops after the step that makes I conclusive")
    {
        Fixture f;
        f.executors[f.A("Rescan")] = &rescan;
        auto& s                    = f.NewSession();
        const auto x               = s.BeginRoot("x", true);
        s.Disclose(f.P("IsPE"), { Subject{ x } });
        s.EndInitialExtraction();
        REQUIRE_FALSE(s.IsFinished());
        REQUIRE(s.LastDecision().reason == InconclusiveReason::NoLabelSatisfied);
        onRescan = [&](DisclosureSink& out) {
            out.Assert(f.P("HasImport"), { out.Self(), "VirtualAlloc" });
            out.Assert(f.P("HasImport"), { out.Self(), "WriteProcessMemory" });
        };
        REQUIRE(s.Step(FindBeta(s, f.A("Rescan"), x)).status == StepStatus::Executed);
        REQUIRE(s.IsFinished());
        REQUIRE(s.GetStopReason() == StopReason::Conclusive);
        REQUIRE(f.spec->interpretation.outcomes.Label(s.LastDecision().outcome) == "Malicious");
    }
    SECTION("does not stop on a lone HasMaliciousness 0.60, nor on a HasBenignity blocked by it")
    {
        // HasMaliciousness 0.60 (< 0.70) keeps Malicious unsatisfied and blocks Benign (> 0.30): the HasBenignity derived by the
        // step is a verdict assertion, but I stays Inconclusive, so the process continues and Rescan(x) stays selectable
        Fixture f;
        f.executors[f.A("Rescan")] = &rescan;
        auto& s                    = f.NewSession();
        const auto x               = s.BeginRoot("setup.exe", true);
        s.Disclose(f.P("IsPE"), { Subject{ x } });
        s.Disclose(f.P("HasImport"), { Subject{ x }, "URLDownloadToFileA" });
        s.EndInitialExtraction();
        REQUIRE(s.Gamma().WithPredicate(f.P("HasMaliciousness")).size() == 1);
        REQUIRE_FALSE(s.IsFinished());
        const auto beta = FindBeta(s, f.A("Rescan"), x);
        onRescan        = [&](DisclosureSink& out) {
            out.Assert(f.P("IsSigned"), { out.Self() });
            out.Assert(f.P("HasValidSignature"), { out.Self() });
        };
        REQUIRE(s.Step(beta).status == StepStatus::Executed);
        REQUIRE(s.Gamma().WithPredicate(f.P("HasBenignity")).size() == 1); // HasBenignity(setup.exe, 0.85)
        REQUIRE_FALSE(s.IsFinished());
        REQUIRE_FALSE(s.LastDecision().conclusive);
        REQUIRE(std::find(s.Selectable().begin(), s.Selectable().end(), beta) != s.Selectable().end());
    }
    SECTION("does not stop after HasBenignity alone while an action is selectable (Benign settles at exhaustion)")
    {
        // (subjects without content: <ReanalyzeSelection>(x) is repeatable and would stay selectable forever)
        Fixture f;
        LambdaExecutor unpack;
        unpack.fn                  = [&](const GroundActionView&, const ActionInput*, DisclosureSink&) { return ActionStatus::Success; };
        f.executors[f.A("Unpack")] = &unpack;
        auto& s                    = f.NewSession();
        const auto x               = s.BeginRoot("signed.zip", false);
        s.Disclose(f.P("IsArchive"), { Subject{ x } });
        s.Disclose(f.P("IsSigned"), { Subject{ x } });
        s.Disclose(f.P("HasValidSignature"), { Subject{ x } });
        s.EndInitialExtraction();
        const auto& before = s.LastDecision();
        REQUIRE(before.outcome.index == BENIGN); // Benign holds on the current knowledge ...
        REQUIRE(before.conclusive);
        REQUIRE(before.settle == SettleMode::Exhaustion);
        REQUIRE_FALSE(before.settled); // ... but Unpack(signed.zip) may still disclose maliciousness
        REQUIRE(before.selectableCount == 1);
        REQUIRE_FALSE(s.IsFinished());
        REQUIRE(
              ExplanationFormatter::DecisionSummary(before, f.spec->interpretation, s.Registry()) ==
              "Benign (provisional, settles at exhaustion: 1 selectable action(s) remain)");
        const auto provisional = ExplanationFormatter::ToMarkdown(Explanation::Build(s, f.spec->interpretation, x), f.spec->interpretation);
        REQUIRE(Contains(provisional, "Benign holds but is not settled: it settles at exhaustion and 1 selectable action(s) remain"));
        // the action discloses nothing new; afterwards nothing is selectable: Benign is settled and the process stops
        REQUIRE(s.Step(FindBeta(s, f.A("Unpack"), x)).status == StepStatus::Executed);
        REQUIRE(s.Selectable().empty());
        REQUIRE(s.IsFinished());
        REQUIRE(s.GetStopReason() == StopReason::Conclusive);
        REQUIRE(s.LastDecision().outcome.index == BENIGN);
        REQUIRE(s.LastDecision().settled);
        REQUIRE(
              ExplanationFormatter::DecisionSummary(s.LastDecision(), f.spec->interpretation, s.Registry()) ==
              "Benign (conclusive, settled: no selectable action remains)");
        const auto settled = ExplanationFormatter::ToMarkdown(Explanation::Build(s, f.spec->interpretation, x), f.spec->interpretation);
        REQUIRE(Contains(settled, "settled: no selectable action remains (Benign settles at exhaustion)"));
    }
    SECTION("HasBenignity alone with no selectable action stops at once with Benign; Malicious settles immediately")
    {
        Fixture f;
        auto& s      = f.NewSession();
        const auto y = s.BeginRoot("signed.dat", false);
        s.Disclose(f.P("IsSigned"), { Subject{ y } });
        s.Disclose(f.P("HasValidSignature"), { Subject{ y } });
        s.EndInitialExtraction();
        REQUIRE(s.Selectable().empty());
        REQUIRE(s.IsFinished());
        REQUIRE(s.GetStopReason() == StopReason::Conclusive);
        REQUIRE(f.spec->interpretation.outcomes.Label(s.LastDecision().outcome) == "Benign");
        REQUIRE(s.LastDecision().settled);
        // Malicious (settle = immediate) stops although actions are selectable
        auto& m      = f.NewSession();
        const auto z = m.BeginRoot("dropper.zip", true);
        m.Disclose(f.P("IsArchive"), { Subject{ z } });
        m.Disclose(f.P("HasMaliciousness"), { Subject{ z }, 0.90 });
        m.EndInitialExtraction();
        REQUIRE_FALSE(m.Selectable().empty());
        REQUIRE(m.IsFinished());
        REQUIRE(m.LastDecision().settle == SettleMode::Immediate);
        REQUIRE(m.LastDecision().settled);
        // the same Gamma interpreted with and without selectable actions (the interpretation itself has no session)
        const auto& interpretation = f.spec->interpretation;
        REQUIRE_FALSE(interpretation.Interpret(s.Gamma(), f.spec->signature, f.spec->pool, s.Registry(), y, 3).settled);
        REQUIRE(interpretation.Interpret(s.Gamma(), f.spec->signature, f.spec->pool, s.Registry(), y, 0).settled);
        REQUIRE(interpretation.Interpret(m.Gamma(), f.spec->signature, f.spec->pool, m.Registry(), z, 3).settled);
    }
    SECTION("manual never stops by itself")
    {
        Fixture f;
        auto& s      = f.NewSession(ManualPolicy());
        const auto x = s.BeginRoot("x", true);
        s.Disclose(f.P("IsPE"), { Subject{ x } });
        s.Disclose(f.P("HasImport"), { Subject{ x }, "VirtualAlloc" });
        s.Disclose(f.P("HasImport"), { Subject{ x }, "WriteProcessMemory" });
        s.EndInitialExtraction();
        REQUIRE(s.LastDecision().conclusive);
        REQUIRE_FALSE(s.IsFinished());
    }
    SECTION("exhaustive stops when nothing is selectable, not before")
    {
        Fixture f;
        // (a subject without content: <ReanalyzeSelection>(x) is repeatable and would stay selectable forever)
        LambdaExecutor unpack;
        unpack.fn                  = [&](const GroundActionView&, const ActionInput*, DisclosureSink&) { return ActionStatus::Success; };
        f.executors[f.A("Unpack")] = &unpack;
        StoppingPolicy policy;
        policy.kind  = StoppingPolicyKind::Exhaustive;
        auto& s      = f.NewSession(policy);
        const auto x = s.BeginRoot("a.zip", false);
        s.Disclose(f.P("IsArchive"), { Subject{ x } });
        s.Disclose(f.P("HasMaliciousness"), { Subject{ x }, 0.90 }); // conclusive, but the policy is exhaustive
        s.EndInitialExtraction();
        REQUIRE(s.LastDecision().conclusive);
        REQUIRE_FALSE(s.IsFinished());
        REQUIRE(s.Selectable().size() == 1);
        REQUIRE(s.Step(FindBeta(s, f.A("Unpack"), x)).status == StepStatus::Executed);
        REQUIRE(s.Selectable().empty());
        REQUIRE(s.IsFinished());
        REQUIRE(s.GetStopReason() == StopReason::NoSelectableActions);
    }
    SECTION("max_steps")
    {
        Fixture f;
        f.executors[f.A("Rescan")] = &rescan;
        StoppingPolicy policy;
        policy.maxSteps = 2;
        auto& s         = f.NewSession(policy);
        const auto x    = s.BeginRoot("x", true);
        s.Disclose(f.P("IsPE"), { Subject{ x } });
        s.EndInitialExtraction();
        const auto beta = FindBeta(s, f.A("Rescan"), x);
        REQUIRE(s.Step(beta).status == StepStatus::Executed);
        REQUIRE_FALSE(s.IsFinished());
        REQUIRE(s.Step(beta).status == StepStatus::Executed);
        REQUIRE(s.IsFinished());
        REQUIRE(s.GetStopReason() == StopReason::PolicyLimit);
        REQUIRE(s.Step(beta).status == StepStatus::Finished);
    }
    SECTION("a custom policy replaces the kind")
    {
        struct StopAfterOneAction : StoppingPolicyInterface {
            mutable uint32 calls{ 0 };
            std::optional<StopReason> ShouldStop(const DisclosureSession& session, const InterpretationDecision& decision) const override
            {
                calls++;
                REQUIRE(&decision == &session.LastDecision());
                return session.Trace().ActionCount() >= 1 ? std::optional<StopReason>(StopReason::PolicyLimit) : std::nullopt;
            }
        } custom;
        Fixture f;
        f.executors[f.A("Rescan")] = &rescan;
        StoppingPolicy policy;
        policy.custom = &custom;
        auto& s       = f.NewSession(policy);
        const auto x  = s.BeginRoot("x", true);
        s.Disclose(f.P("IsPE"), { Subject{ x } });
        s.Disclose(f.P("HasImport"), { Subject{ x }, "VirtualAlloc" });
        s.Disclose(f.P("HasImport"), { Subject{ x }, "WriteProcessMemory" });
        s.EndInitialExtraction();
        REQUIRE(s.LastDecision().conclusive);
        REQUIRE_FALSE(s.IsFinished()); // the custom policy decides, not the conclusive default
        REQUIRE(s.Step(FindBeta(s, f.A("Rescan"), x)).status == StepStatus::Executed);
        REQUIRE(s.IsFinished());
        REQUIRE(s.GetStopReason() == StopReason::PolicyLimit);
        REQUIRE(custom.calls == 2);
    }
    SECTION("manual finish freezes the session and refreshes the decision")
    {
        Fixture f;
        auto& s = f.NewSession();
        REQUIRE_FALSE(s.HasDecision());
        REQUIRE(s.LastDecision().reason == InconclusiveReason::NotEvaluated);
        const auto x = s.BeginRoot("x", true);
        s.EndInitialExtraction();
        REQUIRE(s.HasDecision());
        const auto before = s.Gamma().Size();
        s.Finish(StopReason::ManualStop);
        s.Finish(StopReason::PolicyLimit); // the first stop reason is kept
        REQUIRE(s.GetStopReason() == StopReason::ManualStop);
        REQUIRE(s.LastDecision().input == x);
        REQUIRE(s.LastDecision().reason == InconclusiveReason::NoLabelSatisfied);
        REQUIRE_FALSE(s.Disclose(f.P("IsPE"), { Subject{ x } }));
        s.BeginObservation(x, "late");
        REQUIRE_FALSE(s.IsScopeOpen());
        REQUIRE(s.Gamma().Size() == before);
        REQUIRE(s.Step(0).status == StepStatus::Finished);
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// benchmarks (hidden: run with  libGViewCore.exe "[benchmark]"  in the test build)
// ---------------------------------------------------------------------------------------------------------------------

namespace
{
template <typename F>
double MedianMilliseconds(int runs, F&& f)
{
    std::vector<double> times;
    for (int i = 0; i < runs; i++) {
        const auto start = std::chrono::steady_clock::now();
        f();
        times.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count());
    }
    std::sort(times.begin(), times.end());
    return times[times.size() / 2];
}
} // namespace

TEST_CASE("hdf: benchmark insert 100k assertions", "[.][hdf][benchmark][!benchmark]")
{
    Signature sig;
    sig.AddBuiltins();
    ConstantPool pool(sig.sorts);
    std::string error;
    const ArgumentDeclaration a[] = { { "x", "Subject" }, { "name", "String" }, { "size", "Int" } };
    const auto p                  = *sig.AddPredicate("HasSection", a, "", error);
    std::vector<std::array<ConstantId, 3>> rows;
    for (uint32 i = 0; i < 100000; i++)
        rows.push_back({ pool.InternSubject(sig.subjectSort, i % 1000),
                         pool.InternString(sig.stringSort, "section" + std::to_string(i % 97)),
                         *pool.InternInt(sig.intSort, i) });
    size_t bytes    = 0;
    const double ms = MedianMilliseconds(5, [&] {
        AssertionBase gamma;
        gamma.Reserve(sig.predicates.Count());
        for (const auto& r : rows)
            gamma.Insert(p, r);
        REQUIRE(gamma.Size() == 100000);
        bytes = gamma.MemoryBytes();
    });
    char line[256];
    snprintf(
          line,
          sizeof(line),
          "BENCH insert100k: %.2f ms (%.1f ns/assertion), %.1f bytes/assertion (arity 3)",
          ms,
          ms * 1e6 / 100000,
          static_cast<double>(bytes) / 100000);
    std::cout << line << std::endl;
}

TEST_CASE("hdf: benchmark closure with a 3-literal join over 10k facts", "[.][hdf][benchmark][!benchmark]")
{
    // ExtractedFrom(y, x), IsPE(y), HasImport(y, "VirtualAlloc") |- ContainsInjector(x)  over 10k facts
    auto spec = std::make_unique<LoadedSpecification>();
    auto& sig = spec->signature;
    std::string error;
    const ArgumentDeclaration x[]  = { { "x", "Subject" } };
    const ArgumentDeclaration xa[] = { { "x", "Subject" }, { "api", "String" } };
    const auto isPE                = *sig.AddPredicate("IsPE", x, "", error);
    const auto hasImport           = *sig.AddPredicate("HasImport", xa, "", error);
    sig.AddPredicate("ContainsInjector", x, "", error);
    REQUIRE(spec->specification.AddAssertionRule(
          "R", { "ExtractedFrom(y, x)", "IsPE(y)", "HasImport(y, \"VirtualAlloc\")" }, "ContainsInjector(x)", sig, spec->pool, error));
    spec->specification.Compile(sig);
    const auto va    = spec->pool.InternString(sig.stringSort, "VirtualAlloc");
    const auto other = spec->pool.InternString(sig.stringSort, "CreateFileW");
    uint32 derived   = 0;
    uint32 facts     = 0;
    std::vector<double> closureTimes;
    const double ms = MedianMilliseconds(5, [&] {
        AssertionBase gamma;
        DerivationIndex dt;
        gamma.Reserve(sig.predicates.Count());
        auto add = [&](PredicateId p, std::initializer_list<ConstantId> args) {
            auto r = gamma.Insert(p, std::span<const ConstantId>(args.begin(), args.size()));
            if (r.inserted)
                dt.Record(r.id, DerivationKind::InitialExtraction, 0, 0, 0, 0);
        };
        // 2900 parents with one child each: ExtractedFrom + IsPE (half) + two imports = 10150 facts
        for (uint32 i = 0; i < 2900; i++) {
            const auto parent = spec->pool.InternSubject(sig.subjectSort, i);
            const auto child  = spec->pool.InternSubject(sig.subjectSort, 100000 + i);
            add(sig.extractedFrom, { child, parent });
            if (i % 2 == 0)
                add(isPE, { child });
            add(hasImport, { child, i % 3 == 0 ? va : other });
            add(hasImport, { child, spec->pool.InternString(sig.stringSort, "Api" + std::to_string(i % 50)) });
        }
        facts            = gamma.Size();
        const auto start = std::chrono::steady_clock::now();
        derived          = AssertionEntailment::Close(gamma, spec->specification, 0, dt, 1, DEFAULT_MAX_DERIVED, true).derived;
        closureTimes.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count());
    });
    std::sort(closureTimes.begin(), closureTimes.end());
    REQUIRE(facts == 10150);
    REQUIRE(derived == 484); // i % 6 == 0 for i < 2900
    char line[256];
    snprintf(
          line,
          sizeof(line),
          "BENCH closure3join: %u facts, %u derived, Cl_R %.3f ms (load + Cl_R %.3f ms)",
          facts,
          derived,
          closureTimes[closureTimes.size() / 2],
          ms);
    std::cout << line << std::endl;
}

TEST_CASE("hdf: benchmark Selectable over 1k subjects", "[.][hdf][benchmark][!benchmark]")
{
    Fixture f;
    auto& s      = f.NewSession();
    const auto x = s.BeginRoot("root.zip", true);
    s.Disclose(f.P("IsArchive"), { Subject{ x } });
    std::vector<SubjectId> children;
    for (uint32 i = 0; i < 1000; i++) {
        children.push_back(s.CreateSubject("file" + std::to_string(i), x, true, false));
        s.Disclose(f.P(i % 2 ? "IsPE" : "IsArchive"), { Subject{ children.back() } });
    }
    s.EndInitialExtraction();
    // ReanalyzeSelection for 1001 subjects + Unpack for 501 archives + Rescan for 500 PEs
    REQUIRE(s.Enabled().Size() == 1001 + 501 + 500);
    std::vector<GroundActionId> selectable;
    const double full          = MedianMilliseconds(9, [&] {
        auto enabled = ActionEntailment::EnabledFull(s.Gamma(), f.spec->specification);
        selectable   = ActionEntailment::Selectable(s.Gamma(), f.spec->signature, enabled);
    });
    const double completedOnly = MedianMilliseconds(9, [&] { selectable = ActionEntailment::Selectable(s.Gamma(), f.spec->signature, s.Enabled()); });
    REQUIRE(selectable.size() == 2002);
    char line[256];
    snprintf(
          line,
          sizeof(line),
          "BENCH selectable1k: Enabled(full join)+Selectable %.3f ms, Selectable over the incremental Enabled %.3f ms (%zu ground actions)",
          full,
          completedOnly,
          selectable.size());
    std::cout << line << std::endl;
}
