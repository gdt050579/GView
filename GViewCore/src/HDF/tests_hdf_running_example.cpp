// End-to-end replay of the running example of the HDF chapter: the test reproduces Table tab:hdf-running-example-execution
// row by row. Row 0 is the initial extraction of s0 (Gamma_0); rows 1..10 are the selected actions beta_0..beta_9; the
// final state is Gamma_10. The tool T is a fake over an in-memory artifact tree; the rules are the chapter's rules.
//   s0 = networkTraffic.pcap, c1 = Connection1, c2 = Connection2, s1 = Connection1Data, s2 = Connection2Data,
//   s3 = SuspiciousXMLFragment, s4 = Base64Candidate, s5 = DecodedBase64Data

#include "SpecificationLoader.hpp"
#include "Explanation.hpp"

#include <catch.hpp>

#include <iostream>
#include <map>

using namespace GView::HDF;

namespace
{
constexpr std::string_view RUNNING_EXAMPLE_SPEC = R"JSON({
  "sorts": [ { "name": "Domain", "kind": "String" } ],
  "actions": [
    { "name": "CheckConnections", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "Identify the connections in {x}" },
    { "name": "ExtractConnectionData", "arity": [ { "name": "c", "sort": "Subject" } ], "denotation": "Extract the data transferred over {c}" },
    { "name": "CheckMacros", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "Check {x} for macros" },
    { "name": "CheckScripts", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "Check {x} for scripts" },
    { "name": "CheckBase64", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "Check whether {x} is base64 encoded" },
    { "name": "DecodeBase64", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "Decode the base64 content of {x}" },
    { "name": "CheckSuspicDetails", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "Look for suspicious details in {x}" }
  ],
  "predicates": [
    { "name": "IsPCAP", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} is a network capture" },
    { "name": "IsPicture", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} is a picture" },
    { "name": "IsBMP", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} is a BMP image" },
    { "name": "IsArchive", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} is an archive" },
    { "name": "IsWord", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} is a Word document" },
    { "name": "HasMacros", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} has macros" },
    { "name": "IsXML", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} is an XML document" },
    { "name": "IsBase64", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} is base64 encoded" },
    { "name": "IsPE", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} is a PE file" },
    { "name": "ContainsDomain", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "d", "sort": "Domain" } ], "denotation": "{x} contains the domain {d}" },
    { "name": "UsesCryptoWallets", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} accesses crypto wallets" },
    { "name": "UsesNetworkAPIs", "arity": [ { "name": "x", "sort": "Subject" } ], "denotation": "{x} uses network APIs" },
    { "name": "HasMaliciousness", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "score", "sort": "Real" } ], "denotation": "{x} has maliciousness {score}" },
    { "name": "HasBenignity", "arity": [ { "name": "x", "sort": "Subject" }, { "name": "score", "sort": "Real" } ], "denotation": "{x} has benignity {score}" }
  ],
  "verdicts": [ "HasMaliciousness", "HasBenignity" ],
  "assertion_rules": [
    { "name": "CryptoStealer", "body": [ "ContainsDomain(x, \"http://SomeMaliciousExample.net\")", "UsesCryptoWallets(x)", "UsesNetworkAPIs(x)" ],
      "head": "HasMaliciousness(x, 0.75)", "explanation": "contacts a known malicious domain, accesses crypto wallets and uses network APIs" }
  ],
  "action_rules": [
    { "name": "ConnectionsOfCapture", "body": [ "IsPCAP(x)" ], "head": "CheckConnections(x)" },
    { "name": "DataOfConnection", "body": [ "ExtractedFrom(c, x)", "IsPCAP(x)" ], "head": "ExtractConnectionData(c)" },
    { "name": "MacrosOfWord", "body": [ "IsWord(x)" ], "head": "CheckMacros(x)" },
    { "name": "ScriptsOfWord", "body": [ "IsWord(x)" ], "head": "CheckScripts(x)" },
    { "name": "Base64OfContent", "body": [ "HasContent(x)" ], "head": "CheckBase64(x)" },
    { "name": "DecodeBlob", "body": [ "IsBase64(x)" ], "head": "DecodeBase64(x)" },
    { "name": "InspectExecutable", "body": [ "IsPE(x)" ], "head": "CheckSuspicDetails(x)" }
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

constexpr std::string_view MALICIOUS_DOMAIN = "http://SomeMaliciousExample.net";

// the chapter's short identifiers and the names the subjects carry (HasName)
const std::vector<std::pair<std::string, std::string>> SUBJECT_NAMES = {
    { "s0", "networkTraffic.pcap" }, { "c1", "Connection1" },           { "c2", "Connection2" },     { "s1", "Connection1Data" },
    { "s2", "Connection2Data" },     { "s3", "SuspiciousXMLFragment" }, { "s4", "Base64Candidate" }, { "s5", "DecodedBase64Data" },
};

std::string NameOf(std::string_view shortId)
{
    for (const auto& [id, name] : SUBJECT_NAMES)
        if (id == shortId)
            return name;
    return std::string(shortId);
}

std::string ShortIdOf(std::string_view name)
{
    for (const auto& [id, n] : SUBJECT_NAMES)
        if (n == name)
            return id;
    return std::string(name);
}

// the in-memory artifact tree of tool T
struct Fact {
    std::string predicate;
    std::vector<std::string> extra; // String-kind arguments after the subject
};
struct Artifact {
    std::string name;
    std::vector<Fact> initial; // Init_T(artifact): what opening it discloses (the implicit CheckType)
};
struct Effect {
    std::vector<Fact> self;        // assertions about the subject beta was selected on
    std::vector<Artifact> created; // new subjects extracted from it
};

class FakeTool : public SessionHost, public ActionExecutorInterface
{
  public:
    LoadedSpecification& spec;
    std::map<std::pair<std::string, std::string>, Effect> behaviour; // (action, subject name) -> effect
    DisclosureSession* session{ nullptr };
    uint32 selectionsSeen{ 0 };

    explicit FakeTool(LoadedSpecification& s) : spec(s)
    {
        auto add = [&](std::string action, std::string_view subject, Effect e) { behaviour[{ std::move(action), NameOf(subject) }] = std::move(e); };
        add("CheckConnections", "s0", { {}, { { NameOf("c1"), {} }, { NameOf("c2"), {} } } });
        add("ExtractConnectionData", "c1", { {}, { { NameOf("s1"), { { "IsPicture", {} }, { "IsBMP", {} } } } } });
        add("ExtractConnectionData", "c2", { {}, { { NameOf("s2"), { { "IsArchive", {} }, { "IsWord", {} } } } } });
        add("CheckMacros", "s2", { { { "HasMacros", {} } }, {} });
        add("CheckScripts", "s2", { {}, {} }); // nothing found: the action succeeds, no assertion (only Done_CheckScripts(s2))
        add("ReanalyzeSelection", "s2", { {}, { { NameOf("s3"), { { "IsXML", {} } } } } });
        add("ReanalyzeSelection", "s3", { {}, { { NameOf("s4"), {} } } }); // CheckType identifies no known type
        add("CheckBase64", "s4", { { { "IsBase64", {} } }, {} });
        add("DecodeBase64", "s4", { {}, { { NameOf("s5"), { { "IsPE", {} } } } } });
        add("CheckSuspicDetails",
            "s5",
            { { { "ContainsDomain", { std::string(MALICIOUS_DOMAIN) } }, { "UsesCryptoWallets", {} }, { "UsesNetworkAPIs", {} } }, {} });
    }

    ActionExecutorInterface* ExecutorFor(const DisclosureSession&, GroundActionId) override
    {
        return this;
    }

    bool AssertFact(DisclosureSink& out, Subject s, const Fact& fact)
    {
        std::vector<ArgValue> args{ ArgValue(s) };
        for (const auto& e : fact.extra)
            args.emplace_back(std::string_view(e));
        return out.Assert(spec.signature.predicates.Find(fact.predicate), std::span<const ArgValue>(args));
    }

    ActionStatus Execute(const GroundActionView& action, const ActionInput* input, DisclosureSink& out) override
    {
        const auto self = action.SubjectArg(0);
        if (action.action == spec.signature.reanalyzeSelection) {
            // the analyst selected a fragment of the subject: the range is execution input, not a rule argument
            REQUIRE(input != nullptr);
            REQUIRE(input->selectionSize > 0);
            selectionsSeen++;
        }
        auto it = behaviour.find({ std::string(action.name), session->Registry().Get(self.id).name });
        if (it == behaviour.end())
            return ActionStatus::Failed;
        for (const auto& fact : it->second.self)
            REQUIRE(AssertFact(out, self, fact));
        for (const auto& artifact : it->second.created) {
            const auto child = out.CreateSubject(artifact.name, self);
            REQUIRE(child.IsValid());
            // opening the new subject: its initial extraction belongs to Gamma_beta (implicit CheckType)
            for (const auto& fact : artifact.initial)
                REQUIRE(AssertFact(out, child, fact));
        }
        return ActionStatus::Success;
    }
};

// one row of the chapter's table (rows 1..10)
struct PlannedStep {
    const char* action;
    const char* subject;                // short id
    std::vector<std::string> disclosed; // Gamma_beta as printed in the chapter (built-in HasName/HasContent omitted)
    std::vector<std::string> derived;   // Cl_R
};

const std::vector<std::string> ROW0 = { "IsPCAP(s0)" };

const std::vector<PlannedStep> PLAN = {
    { "CheckConnections", "s0", { "ExtractedFrom(c1, s0)", "ExtractedFrom(c2, s0)" }, {} },
    { "ExtractConnectionData", "c1", { "ExtractedFrom(s1, c1)", "IsPicture(s1)", "IsBMP(s1)" }, {} },
    { "ExtractConnectionData", "c2", { "ExtractedFrom(s2, c2)", "IsArchive(s2)", "IsWord(s2)" }, {} },
    { "CheckMacros", "s2", { "HasMacros(s2)" }, {} },
    { "CheckScripts", "s2", {}, {} },
    { "ReanalyzeSelection", "s2", { "ExtractedFrom(s3, s2)", "IsXML(s3)" }, {} },
    { "ReanalyzeSelection", "s3", { "ExtractedFrom(s4, s3)" }, {} },
    { "CheckBase64", "s4", { "IsBase64(s4)" }, {} },
    { "DecodeBase64", "s4", { "ExtractedFrom(s5, s4)", "IsPE(s5)" }, {} },
    { "CheckSuspicDetails",
      "s5",
      { "ContainsDomain(s5, \"http://SomeMaliciousExample.net\")", "UsesCryptoWallets(s5)", "UsesNetworkAPIs(s5)" },
      { "HasMaliciousness(s5, 0.75)" } },
};

SubjectId FindSubject(const DisclosureSession& s, std::string_view shortId)
{
    const auto name = NameOf(shortId);
    for (SubjectId id = 0; id < s.Registry().Count(); id++)
        if (s.Registry().Get(id).name == name && s.OwnsSubject(id))
            return id;
    return INVALID_SUBJECT_ID;
}

std::string ShortConstant(const DisclosureSession& s, ConstantId c)
{
    if (s.Pool().Kind(c) == SortKind::Subject)
        return ShortIdOf(s.Registry().Get(s.Pool().AsSubject(c)).name);
    return s.Pool().Format(c, true);
}

// an atom with the chapter's short subject ids and quoted strings, e.g. ContainsDomain(s5, "http://...")
std::string ShortAtom(const DisclosureSession& s, AssertionId a)
{
    std::string text = s.GetSignature().predicates.Get(s.Gamma().Predicate(a)).name + "(";
    bool first       = true;
    for (const auto c : s.Gamma().Args(a)) {
        text += (first ? "" : ", ") + ShortConstant(s, c);
        first = false;
    }
    return text + ")";
}

std::string ShortAction(const DisclosureSession& s, GroundActionId beta)
{
    std::string text = "<" + s.GetSignature().actions.Get(s.Enabled().Get(beta).action).name + ">(";
    bool first       = true;
    for (const auto c : s.Enabled().Args(beta)) {
        text += (first ? "" : ", ") + ShortConstant(s, c);
        first = false;
    }
    return text + ")";
}

bool IsBuiltinProvenance(const DisclosureSession& s, AssertionId a)
{
    const auto p = s.Gamma().Predicate(a);
    return p == s.GetSignature().hasName || p == s.GetSignature().hasContent;
}

// Gamma_beta as printed in the chapter: [disclosedBegin, disclosedEnd) without HasName / HasContent
std::vector<std::string> ChapterDisclosed(const DisclosureSession& s, const DisclosureTransition& tr)
{
    std::vector<std::string> atoms;
    for (AssertionId a = tr.disclosedBegin; a < tr.disclosedEnd; a++)
        if (!IsBuiltinProvenance(s, a))
            atoms.push_back(ShortAtom(s, a));
    return atoms;
}

// what Cl_R added: [disclosedEnd (+1 when D_beta is present), toCount)
std::vector<std::string> Derived(const DisclosureSession& s, const DisclosureTransition& tr)
{
    std::vector<std::string> atoms;
    const AssertionId from = tr.completionAssertion != INVALID_ASSERTION_ID ? tr.completionAssertion + 1 : tr.disclosedEnd;
    for (AssertionId a = from; a < tr.toCount; a++)
        atoms.push_back(ShortAtom(s, a));
    return atoms;
}

std::string Join(const std::vector<std::string>& items)
{
    std::string text;
    for (const auto& i : items)
        text += (text.empty() ? "" : ", ") + i;
    return "{" + text + "}";
}

// the chapter's table: row 0 = Init_T(s0), rows 1..10 = beta_0..beta_9
std::string ChapterTable(const DisclosureSession& s)
{
    std::string text  = "| row | selected action | Gamma_beta | D_beta | derived by Cl_R | |Gamma_i+1| |\n|---|---|---|---|---|---|\n";
    const auto& trace = s.Trace();
    for (uint32 t = 0; t < trace.Size(); t++) {
        const auto& tr = trace.transitions[t];
        if (tr.kind == TransitionKind::InitialExtraction) {
            text += "| 0 | initial extraction of s0 (Gamma_0) | " + Join(ChapterDisclosed(s, tr)) + " | - | " + Join(Derived(s, tr)) + " | " +
                    std::to_string(tr.toCount) + " |\n";
            continue;
        }
        const auto i           = trace.StepIndex(t);
        const std::string done = tr.completionAssertion != INVALID_ASSERTION_ID ? ShortAtom(s, tr.completionAssertion) : std::string("- (repeatable)");
        text += "| " + std::to_string(i + 1) + " | beta_" + std::to_string(i) + " = " + ShortAction(s, tr.action) + " | " + Join(ChapterDisclosed(s, tr)) +
                " | " + done + " | " + Join(Derived(s, tr)) + " | " + std::to_string(tr.toCount) + " |\n";
    }
    return text;
}

// replays row 0 and the first `steps` rows of PLAN; returns the root
SubjectId Replay(FakeTool& tool, DisclosureSession& s, size_t steps)
{
    tool.session    = &s;
    const auto root = s.BeginRoot(NameOf("s0"), true);
    REQUIRE(s.Disclose(tool.spec.signature.predicates.Find("IsPCAP"), { Subject{ root } }));
    s.EndInitialExtraction();
    REQUIRE(s.HasInitialState());
    REQUIRE(ChapterDisclosed(s, s.Trace().transitions[0]) == ROW0);
    for (size_t i = 0; i < steps; i++) {
        const auto& step   = PLAN[i];
        const auto subject = FindSubject(s, step.subject);
        INFO("row " << i + 1 << ": " << step.action << "(" << step.subject << ")");
        REQUIRE(subject != INVALID_SUBJECT_ID);
        const ConstantId c = s.SubjectConstant(subject);
        const auto action  = tool.spec.signature.actions.Find(step.action);
        const auto beta    = s.FindSelectable(action, std::span<const ConstantId>(&c, 1));
        REQUIRE(beta != INVALID_GROUND_ACTION_ID); // beta_i in Selectable(Gamma_i)
        const ActionInput selection{ 0x100 * (i + 1), 0x40 };
        const auto result = s.Step(beta, action == tool.spec.signature.reanalyzeSelection ? &selection : nullptr);
        REQUIRE(result.status == StepStatus::Executed);
        REQUIRE(result.actionStatus == ActionStatus::Success);
        const auto& tr = s.Trace().transitions[result.transition];
        REQUIRE(s.Trace().StepIndex(result.transition) == i);
        REQUIRE(ChapterDisclosed(s, tr) == step.disclosed);
        // D_beta: Done_a(c) for every non-repeatable action; ReanalyzeSelection is repeatable
        if (tool.spec.signature.actions.Get(action).repeatable) {
            REQUIRE(tr.completionAssertion == INVALID_ASSERTION_ID);
        } else {
            REQUIRE(tr.completionAssertion != INVALID_ASSERTION_ID);
            REQUIRE(ShortAtom(s, tr.completionAssertion) == "Done_" + std::string(step.action) + "(" + step.subject + ")");
        }
        REQUIRE(Derived(s, tr) == step.derived);
    }
    return root;
}
} // namespace

TEST_CASE("hdf: running example (chapter table steps 0-10)", "[hdf][running-example]")
{
    Diagnostics d;
    auto spec = LoadSpecificationText(RUNNING_EXAMPLE_SPEC, d);
    INFO(d.ToText());
    REQUIRE(spec);
    REQUIRE_FALSE(d.HasErrors());
    FakeTool tool(*spec);
    SubjectRegistry registry;
    DisclosureSession s(0, spec->signature, spec->specification, spec->interpretation, spec->pool, registry, &tool, spec->stopping, DEFAULT_MAX_DERIVED);
    const auto root = Replay(tool, s, PLAN.size());

    REQUIRE(s.Trace().transitions[0].kind == TransitionKind::InitialExtraction);
    REQUIRE(s.Trace().ActionCount() == 10); // beta_0 .. beta_9 => Gamma_10
    REQUIRE(tool.selectionsSeen == 2);      // rows 6 and 7 are ReanalyzeSelection with a selected fragment

    // HasMaliciousness(s5, 0.75) in Gamma_10
    const auto s5              = FindSubject(s, "s5");
    const ConstantId verdict[] = { s.SubjectConstant(s5), *spec->pool.InternReal(spec->signature.realSort, 0.75) };
    REQUIRE(s.Gamma().Contains(spec->signature.predicates.Find("HasMaliciousness"), verdict));
    REQUIRE(s.Gamma().Size() == 44); // |Gamma_10|

    // I(Gamma_10, tau_s0) is conclusive: the process stops by itself after beta_9 with (Gamma_10, tau_s0);
    // I = Malicious via s0 -> c2 -> s2 -> s3 -> s4 -> s5
    REQUIRE(s.IsFinished());
    REQUIRE(s.GetStopReason() == StopReason::Conclusive);
    REQUIRE(s.Result().stopReason == StopReason::Conclusive);
    REQUIRE(s.Result().finalState.assertionCount == s.Gamma().Size());
    const auto e = Explanation::Build(s, spec->interpretation, root);
    REQUIRE(e.outcome == "Malicious");
    REQUIRE(e.decision.conclusive);
    REQUIRE(e.decision.deciding == s5);
    REQUIRE(e.decision.input == root);
    std::vector<std::string> path;
    for (auto it = e.decision.provenancePath.rbegin(); it != e.decision.provenancePath.rend(); ++it)
        path.push_back(ShortIdOf(s.Registry().Get(*it).name));
    REQUIRE(path == std::vector<std::string>{ "s0", "c2", "s2", "s3", "s4", "s5" });
    const auto md = ExplanationFormatter::ToMarkdown(e, spec->interpretation);
    REQUIRE(md.find("I_subj(networkTraffic.pcap) = Inconclusive (no label satisfied)") != std::string::npos);
    REQUIRE(
          md.find("I_subj(DecodedBase64Data) = Malicious, propagated to networkTraffic.pcap along networkTraffic.pcap -> Connection2 -> "
                  "Connection2Data -> SuspiciousXMLFragment -> Base64Candidate -> DecodedBase64Data") != std::string::npos);
    REQUIRE(md.find("HasMaliciousness(DecodedBase64Data, .) = max{0.75} = 0.75 >= 0.70 [holds]") != std::string::npos);
    REQUIRE(md.find("no HasBenignity(DecodedBase64Data, c) with c >= 0.70 [holds: no assertion]") != std::string::npos);
    REQUIRE(
          md.find("networkTraffic.pcap -> Connection2 -> Connection2Data -> SuspiciousXMLFragment -> Base64Candidate -> DecodedBase64Data") !=
          std::string::npos);
    REQUIRE(md.find("## Stop reason\nconclusive") != std::string::npos);
    // one witness: the DT of HasMaliciousness(s5, 0.75) reaches back to the initial extraction of s0 through the enabling premises
    REQUIRE(e.witnesses.size() == 1);
    REQUIRE(ShortAtom(s, e.witnesses[0].first) == "HasMaliciousness(s5, 0.75)");
    bool reachesRoot = false;
    for (const auto& node : e.witnesses[0].second.nodes)
        reachesRoot |= s.Derivations().Get(node.assertion).kind == DerivationKind::InitialExtraction;
    REQUIRE(reachesRoot);
    REQUIRE(md.find("Rule CryptoStealer: ") != std::string::npos);
    // the frozen session refuses further steps
    REQUIRE(s.Step(0).status == StepStatus::Finished);

    std::cout << "\n==== HDF running example: Table tab:hdf-running-example-execution ====\n"
              << ChapterTable(s) << "\n==== HDF running example: explanation ====\n"
              << md << std::endl;
}

TEST_CASE("hdf: running example stopped before step 10 is Inconclusive", "[hdf][running-example]")
{
    Diagnostics d;
    auto spec = LoadSpecificationText(RUNNING_EXAMPLE_SPEC, d);
    REQUIRE(spec);
    FakeTool tool(*spec);
    SubjectRegistry registry;
    DisclosureSession s(0, spec->signature, spec->specification, spec->interpretation, spec->pool, registry, &tool, spec->stopping, DEFAULT_MAX_DERIVED);
    const auto root = Replay(tool, s, PLAN.size() - 1); // beta_0 .. beta_8 => Gamma_9
    REQUIRE_FALSE(s.IsFinished());                      // I(Gamma_9) is Inconclusive: the process continues
    REQUIRE_FALSE(s.LastDecision().conclusive);
    s.Finish(StopReason::ManualStop);
    const auto e = Explanation::Build(s, spec->interpretation, root);
    REQUIRE(e.outcome == "Inconclusive");
    REQUIRE(e.decision.reason == InconclusiveReason::NoLabelSatisfied);
    REQUIRE(e.witnesses.empty());
    REQUIRE(e.stopReason == StopReason::ManualStop);
    const auto md = ExplanationFormatter::ToMarkdown(e, spec->interpretation);
    REQUIRE(md.find("reason: no label satisfied") != std::string::npos);
    REQUIRE(md.find("Malicious (propagating) fails for all 8 subjects of the provenance tree:") != std::string::npos);
    REQUIRE(md.find("    HasMaliciousness(DecodedBase64Data, .) missing [fails]") != std::string::npos);
    REQUIRE(md.find("  Benign: HasBenignity(networkTraffic.pcap, .) missing [fails]") != std::string::npos);
    REQUIRE(md.find("core stop reason: manual stop") != std::string::npos);
    REQUIRE(s.Result().stopReason == StopReason::ManualStop);
    // CheckSuspicDetails(s5) was selectable when the analyst stopped
    const auto s5       = FindSubject(s, "s5");
    const ConstantId c5 = s.SubjectConstant(s5);
    REQUIRE(s.FindSelectable(spec->signature.actions.Find("CheckSuspicDetails"), std::span<const ConstantId>(&c5, 1)) != INVALID_GROUND_ACTION_ID);
}
