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
    { "name": "HasMaliciousness", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "score", "sort": "Real" } ], "denotation": "{x} has maliciousness {score}" }
  ],
  "verdicts": [ "HasMaliciousness" ],
  "assertion_rules": [
    { "name": "Contains", "body": [ "ExtractedFrom(y, x)", "IsPE(y)" ], "head": "ContainsExecutable(x)" },
    { "name": "Inject", "body": [ "IsPE(x)", "HasImport(x, \"VirtualAlloc\")", "HasImport(x, \"WriteProcessMemory\")" ], "head": "Injection(x)", "explanation": "allocates and writes memory in another process" },
    { "name": "Verdict", "body": [ "Injection(x)" ], "head": "HasMaliciousness(x, 0.8)" }
  ],
  "action_rules": [
    { "name": "UnpackArchive", "body": [ "IsArchive(x)" ], "head": "Unpack(x)" },
    { "name": "RescanPE", "body": [ "IsPE(x)" ], "head": "Rescan(x)" }
  ],
  "interpretation": {
    "outcomes": [ "Malicious", "Suspicious", "Benign", "Inconclusive" ],
    "fallback": "Inconclusive",
    "verdicts": [ { "predicate": "HasMaliciousness", "aggregate": "max",
                    "conditions": [ { "outcome": "Malicious", "op": ">=", "value": 0.7 },
                                    { "outcome": "Suspicious", "op": ">=", "value": 0.4 },
                                    { "outcome": "Benign", "op": "<=", "value": 0.3 } ] } ]
  },
  "stopping": { "on_verdict": false, "max_steps": 0 }
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
              static_cast<uint32>(sessions.size()), spec->signature, spec->specification, spec->pool, registry, this, policy, maxDerived));
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
} // namespace

TEST_CASE("hdf: loader validation", "[hdf]")
{
    using S = Diagnostic::Severity;
    // (MSVC does not accept raw string literals inside macro arguments: the cases are data)
    struct Case {
        std::string json;
        std::string_view fragment; // expected in an error (empty: the document must load without errors)
    };
    const std::string V           = R"J({ "name": "V", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "s", "sort": "Real" } ] })J";
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
        // the outcome set must contain Inconclusive
        { R"J({ "interpretation": { "outcomes": [ "Malicious", "Benign" ], "fallback": "Benign" } })J", "Inconclusive" },
        // the interpretation may only reference verdict predicates
        { R"J({ "predicates": [ )J" + V + R"J( ], "interpretation": { "outcomes": [ "Inconclusive" ], "verdicts": [ { "predicate": "V" } ] } })J",
          "not a verdict predicate" },
        // bad aggregate / outcome / operator
        { R"J({ "predicates": [ )J" + V + R"J( ], "verdicts": [ "V" ],
               "interpretation": { "outcomes": [ "Inconclusive" ], "verdicts": [ { "predicate": "V", "aggregate": "median" } ] } })J",
          "unknown aggregate" },
        { R"J({ "predicates": [ )J" + V + R"J( ], "verdicts": [ "V" ],
               "interpretation": { "outcomes": [ "Inconclusive" ], "verdicts": [ { "predicate": "V", "conditions": [ { "outcome": "X", "op": ">=", "value": 1 } ] } ] } })J",
          "unknown outcome" },
        { R"J({ "predicates": [ )J" + V + R"J( ], "verdicts": [ "V" ],
               "interpretation": { "outcomes": [ "Inconclusive" ], "verdicts": [ { "predicate": "V", "conditions": [ { "outcome": "Inconclusive", "op": "~", "value": 1 } ] } ] } })J",
          "unknown operator" },
        // wrong types are errors
        { R"J({ "predicates": { } })J", "must be an array" },
        { R"J({ "stopping": { "max_steps": -3 } })J", "non-negative" },
        { R"J({ "stopping": { "on_verdict": "yes" } })J", "must be a boolean" },
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

TEST_CASE("hdf: interpretation aggregate and classify", "[hdf]")
{
    const double scores[] = { 0.2, 0.5, 0.9 };
    REQUIRE(Interpretation::Aggregate(AggregateFunction::Max, scores) == 0.9);
    REQUIRE(Interpretation::Aggregate(AggregateFunction::Min, scores) == 0.2);
    REQUIRE(Interpretation::Aggregate(AggregateFunction::Mean, scores) == Catch::Approx(1.6 / 3));
    REQUIRE(Interpretation::Aggregate(AggregateFunction::NoisyOr, scores) == Catch::Approx(1.0 - 0.8 * 0.5 * 0.1));
    const double clampTest[] = { 1.5, -2.0 };
    REQUIRE(Interpretation::Aggregate(AggregateFunction::NoisyOr, clampTest) == Catch::Approx(1.0));
    REQUIRE(Interpretation::Aggregate(AggregateFunction::Max, std::span<const double>()) == 0.0);

    Fixture f;
    const auto& interpretation = f.spec->interpretation;
    REQUIRE(interpretation.outcomes.Label({ interpretation.outcomes.fallbackIndex }) == "Inconclusive");
    const auto* vi = interpretation.Find(f.P("HasMaliciousness"));
    REQUIRE(vi);
    REQUIRE(Interpretation::Classify(*vi, 0.75) == 0);  // >= 0.7 Malicious
    REQUIRE(Interpretation::Classify(*vi, 0.5) == 1);   // >= 0.4 Suspicious
    REQUIRE(Interpretation::Classify(*vi, 0.1) == 2);   // <= 0.3 Benign
    REQUIRE(Interpretation::Classify(*vi, 0.35) == -1); // fallback

    auto& s           = f.NewSession();
    const auto x      = s.BeginRoot("root", true);
    const auto a      = s.CreateSubject("a", x, true, false);
    const auto b      = s.CreateSubject("b", a, true, false);
    const auto c      = s.CreateSubject("c", x, true, false);
    const auto lonely = s.CreateSubject("lonely", x, true, false);
    s.EndInitialExtraction();
    auto interpret = [&](SubjectId root) { return interpretation.Interpret(s.Gamma(), f.spec->signature, f.spec->pool, s.Registry(), root); };
    // no verdict assertion => fallback
    auto d0 = interpret(x);
    REQUIRE_FALSE(d0.fromVerdict);
    REQUIRE(interpretation.outcomes.Label(d0.outcome) == "Inconclusive");

    const auto mal = f.P("HasMaliciousness");
    s.Disclose(mal, { Subject{ x }, 0.1 });
    REQUIRE(interpretation.outcomes.Label(interpret(x).outcome) == "Benign");
    // multiple verdict assertions of one subject: max aggregate
    s.Disclose(mal, { Subject{ c }, 0.2 });
    s.Disclose(mal, { Subject{ c }, 0.45 });
    auto d1 = interpret(x);
    REQUIRE(interpretation.outcomes.Label(d1.outcome) == "Suspicious");
    REQUIRE(d1.subject == c);
    REQUIRE(d1.assertionCount == 2);
    REQUIRE(d1.score == 0.45);
    REQUIRE(d1.provenancePath == std::vector<SubjectId>{ c, x });
    // the deepest subject has the highest priority outcome => it decides; path b -> a -> root
    s.Disclose(mal, { Subject{ b }, 0.95 });
    auto d2 = interpret(x);
    REQUIRE(interpretation.outcomes.Label(d2.outcome) == "Malicious");
    REQUIRE(d2.subject == b);
    REQUIRE(d2.provenancePath == std::vector<SubjectId>{ b, a, x });
    REQUIRE(d2.conditionIndex == 0);
    // same outcome closer to the root wins
    s.Disclose(mal, { Subject{ a }, 0.8 });
    REQUIRE(interpret(x).subject == a);
    // a sub-tree is interpreted on its own
    REQUIRE(interpretation.outcomes.Label(interpret(lonely).outcome) == "Inconclusive");
    REQUIRE(interpret(b).subject == b);
    // two subjects at the same distance with the same outcome => lowest SubjectId
    s.Disclose(mal, { Subject{ lonely }, 0.99 });
    REQUIRE(interpret(x).subject == a); // a was created before lonely
}

TEST_CASE("hdf: interpretation with mean and noisy_or aggregation", "[hdf]")
{
    std::string json(CORE_SPEC);
    const auto at = json.find("\"aggregate\": \"max\"");
    REQUIRE(at != std::string::npos);
    for (const auto* aggregate : { "mean", "noisy_or" }) {
        std::string changed = json;
        changed.replace(at, std::string("\"aggregate\": \"max\"").size(), std::string("\"aggregate\": \"") + aggregate + "\"");
        Fixture f(changed);
        auto& s      = f.NewSession();
        const auto x = s.BeginRoot("x", true);
        s.Disclose(f.P("HasMaliciousness"), { Subject{ x }, 0.5 });
        s.Disclose(f.P("HasMaliciousness"), { Subject{ x }, 0.5 });
        s.EndInitialExtraction();
        const auto d = f.spec->interpretation.Interpret(s.Gamma(), f.spec->signature, f.spec->pool, s.Registry(), x);
        // the same score is one constant: set semantics keeps a single HasMaliciousness(x, 0.5)
        REQUIRE(d.assertionCount == 1);
        s.Disclose(f.P("HasMaliciousness"), { Subject{ x }, 0.6 });
        const auto d2 = f.spec->interpretation.Interpret(s.Gamma(), f.spec->signature, f.spec->pool, s.Registry(), x);
        if (std::string_view(aggregate) == "mean") {
            REQUIRE(d2.score == Catch::Approx(0.55));
            REQUIRE(f.spec->interpretation.outcomes.Label(d2.outcome) == "Suspicious");
        } else {
            REQUIRE(d2.score == Catch::Approx(0.8));
            REQUIRE(f.spec->interpretation.outcomes.Label(d2.outcome) == "Malicious");
        }
    }
}

TEST_CASE("hdf: explanation contains the interpretation step and the stop reason", "[hdf]")
{
    Fixture f;
    auto& s      = f.NewSession();
    const auto x = s.BeginRoot("sample.exe", true);
    s.Disclose(f.P("IsPE"), { Subject{ x } });
    s.Disclose(f.P("HasImport"), { Subject{ x }, "VirtualAlloc" });
    s.Disclose(f.P("HasImport"), { Subject{ x }, "WriteProcessMemory" });
    s.EndInitialExtraction();
    REQUIRE(s.VerdictReached());
    REQUIRE_FALSE(s.IsFinished()); // a verdict is reported, it does not stop the process
    s.Finish(StopReason::ManualStop);
    const auto e  = Explanation::Build(s, f.spec->interpretation, x);
    const auto md = ExplanationFormatter::ToMarkdown(e, f.spec->interpretation);
    REQUIRE(e.outcome == "Malicious");
    REQUIRE(md.find("max over 1 assertion(s) = 0.80; 0.80 >= 0.70 => Malicious") != std::string::npos);
    REQUIRE(md.find("manual stop") != std::string::npos);
    REQUIRE(md.find("Rule Verdict: Injection(x) |- HasMaliciousness(x, 0.80)") != std::string::npos);
    REQUIRE(md.find("sample.exe can inject code") != std::string::npos);
    REQUIRE(md.find("Why: ") == std::string::npos); // the Verdict rule has no explanation
    REQUIRE(md.find("allocates and writes memory") == std::string::npos);
    const auto treeText = ExplanationFormatter::DerivationTreeText(s, e.tree);
    REQUIRE(treeText.find("rule Inject") != std::string::npos);
    REQUIRE(treeText.find("initial extraction") != std::string::npos);
}

TEST_CASE("hdf: stopping policy", "[hdf]")
{
    SECTION("on_verdict stops the process")
    {
        Fixture f;
        StoppingPolicy policy;
        policy.stopOnVerdict = true;
        auto& s              = f.NewSession(policy);
        const auto x         = s.BeginRoot("x", true);
        s.Disclose(f.P("IsPE"), { Subject{ x } });
        s.Disclose(f.P("HasImport"), { Subject{ x }, "VirtualAlloc" });
        s.Disclose(f.P("HasImport"), { Subject{ x }, "WriteProcessMemory" });
        s.EndInitialExtraction();
        REQUIRE(s.IsFinished());
        REQUIRE(s.GetStopReason() == StopReason::VerdictReached);
        REQUIRE(s.Result().stopReason == StopReason::VerdictReached);
    }
    SECTION("max_steps")
    {
        Fixture f;
        LambdaExecutor rescan;
        rescan.fn                  = [](const GroundActionView&, const ActionInput*, DisclosureSink&) { return ActionStatus::Success; };
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
    SECTION("manual finish freezes the session")
    {
        Fixture f;
        auto& s      = f.NewSession();
        const auto x = s.BeginRoot("x", true);
        s.EndInitialExtraction();
        const auto before = s.Gamma().Size();
        s.Finish(StopReason::ManualStop);
        s.Finish(StopReason::PolicyLimit); // the first stop reason is kept
        REQUIRE(s.GetStopReason() == StopReason::ManualStop);
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
