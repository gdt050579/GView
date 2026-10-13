#include "Explanation.hpp"

#include <cstdio>

namespace GView::HDF
{
std::string Denotation::Constant(const ConstantPool& pool, const SubjectRegistry& registry, ConstantId c)
{
    if (pool.IsValid(c) && pool.Kind(c) == SortKind::Subject) {
        const auto s = pool.AsSubject(c);
        if (registry.IsValid(s) && !registry.Get(s).name.empty())
            return registry.Get(s).name;
    }
    return pool.Format(c, false);
}

std::string Denotation::Render(
      const DenotationTemplate& den, std::string_view symbolName, std::span<const ConstantId> args, const ConstantPool& pool, const SubjectRegistry& registry)
{
    std::string result;
    if (den.Empty()) {
        result.append(symbolName);
        result.push_back('(');
        for (size_t i = 0; i < args.size(); i++) {
            if (i > 0)
                result.append(", ");
            result.append(Constant(pool, registry, args[i]));
        }
        result.push_back(')');
        return result;
    }
    for (const auto& piece : den.pieces) {
        if (piece.argument < 0)
            result.append(den.text, piece.offset, piece.length);
        else if (static_cast<size_t>(piece.argument) < args.size())
            result.append(Constant(pool, registry, args[piece.argument]));
    }
    return result;
}

std::string Denotation::Assertion(const DisclosureSession& session, AssertionId id)
{
    const auto& gamma = session.Gamma();
    if (id >= gamma.Size())
        return "?";
    const auto& symbol = session.GetSignature().predicates.Get(gamma.Predicate(id));
    return Render(symbol.denotation, symbol.name, gamma.Args(id), session.Pool(), session.Registry());
}

std::string Denotation::Atom(const DisclosureSession& session, AssertionId id)
{
    const auto& gamma = session.Gamma();
    if (id >= gamma.Size())
        return "?";
    const auto& symbol = session.GetSignature().predicates.Get(gamma.Predicate(id));
    return Render(DenotationTemplate{}, symbol.name, gamma.Args(id), session.Pool(), session.Registry());
}

std::string Denotation::Action(const DisclosureSession& session, GroundActionId beta)
{
    const auto& enabled = session.Enabled();
    if (beta >= enabled.Size())
        return "?";
    const auto& symbol = session.GetSignature().actions.Get(enabled.Get(beta).action);
    return Render(symbol.denotation, symbol.name, enabled.Args(beta), session.Pool(), session.Registry());
}

std::string Denotation::ActionAtom(const DisclosureSession& session, GroundActionId beta)
{
    const auto& enabled = session.Enabled();
    if (beta >= enabled.Size())
        return "?";
    const auto& symbol = session.GetSignature().actions.Get(enabled.Get(beta).action);
    std::string result = "<" + symbol.name + ">";
    result += Render(DenotationTemplate{}, "", enabled.Args(beta), session.Pool(), session.Registry());
    return result;
}

std::string Denotation::Source(const DisclosureSession& session, AssertionId id)
{
    const auto& dt = session.Derivations();
    if (id >= dt.Size())
        return "?";
    const auto& record = dt.Get(id);
    switch (record.kind) {
    case DerivationKind::InitialExtraction:
        return "initial extraction";
    case DerivationKind::Observation:
        return "observation '" + std::string(session.Pool().Strings().Get(record.ruleOrAction)) + "'";
    case DerivationKind::Rule:
        return "rule " + (record.ruleOrAction < session.GetSpecification().assertionRules.size()
                                ? session.GetSpecification().assertionRules[record.ruleOrAction].name
                                : std::string("?"));
    case DerivationKind::Action:
    case DerivationKind::Completion: {
        std::string text = record.kind == DerivationKind::Action ? "disclosed by " : "completion of ";
        text += ActionAtom(session, record.ruleOrAction);
        if (record.transition < session.Trace().Size())
            text += " (step " + std::to_string(session.Trace().StepIndex(record.transition)) + ")";
        return text;
    }
    }
    return "?";
}

Explanation Explanation::Build(const DisclosureSession& session, const Interpretation& interpretation, SubjectId root)
{
    Explanation e;
    e.session    = &session;
    e.root       = root;
    e.decision   = interpretation.Interpret(session.Gamma(), session.GetSignature(), session.Pool(), session.Registry(), root);
    e.outcome    = std::string(interpretation.outcomes.Label(e.decision.outcome));
    e.stopReason = session.GetStopReason();
    e.finalState = session.State();
    if (e.decision.fromVerdict && e.decision.verdictAssertion != INVALID_ASSERTION_ID)
        e.tree = DerivationTree::Build(session.Derivations(), e.decision.verdictAssertion);
    return e;
}

std::string ExplanationFormatter::DerivationTreeText(const DisclosureSession& session, const DerivationTree& tree)
{
    std::string text;
    for (const auto& node : tree.nodes) {
        text.append(static_cast<size_t>(node.depth) * 2, ' ');
        text.append("- ");
        text.append(Denotation::Assertion(session, node.assertion));
        text.append("   [");
        text.append(Denotation::Atom(session, node.assertion));
        text.append("; ");
        text.append(Denotation::Source(session, node.assertion));
        text.append(node.repeated ? "; derivation shown above]\n" : "]\n");
    }
    if (tree.truncated)
        text.append("  ... (derivation tree truncated)\n");
    return text;
}

std::string ExplanationFormatter::InterpretationStep(const Explanation& e, const Interpretation& interpretation)
{
    const auto& d = e.decision;
    if (!d.fromVerdict)
        return "no verdict assertion in the provenance tree of the subject => " + e.outcome + " (fallback)";
    const auto& session = *e.session;
    char score[64];
    snprintf(score, sizeof(score), "%.2f", d.score);
    std::string text = std::string(session.GetSignature().predicates.Get(d.predicate).name) + "(" + session.Registry().Get(d.subject).name +
                       ", .): " + std::string(AggregateFunctionName(d.aggregate)) + " over " + std::to_string(d.assertionCount) + " assertion(s) = " + score +
                       "; ";
    const auto* vi = interpretation.Find(d.predicate);
    if (d.conditionIndex >= 0 && vi && static_cast<size_t>(d.conditionIndex) < vi->conditions.size()) {
        const auto& c = vi->conditions[d.conditionIndex];
        char value[64];
        snprintf(value, sizeof(value), "%.2f", c.value);
        text += std::string(score) + " " + std::string(ComparisonOperatorName(c.op)) + " " + value + " => " + e.outcome;
    } else {
        text += "no condition matched => " + e.outcome + " (fallback)";
    }
    return text;
}

std::string ExplanationFormatter::TraceTable(const DisclosureSession& session)
{
    std::string text  = "| step | beta_i | Gamma_beta_i | |Gamma_i+1| |\n|---|---|---|---|\n";
    const auto& trace = session.Trace();
    const auto& gamma = session.Gamma();
    for (uint32 t = 0; t < trace.Size(); t++) {
        const auto& tr = trace.transitions[t];
        std::string step, beta;
        switch (tr.kind) {
        case TransitionKind::InitialExtraction:
            step = "init";
            beta = "Init_T(" + (session.Registry().IsValid(tr.subject) ? session.Registry().Get(tr.subject).name : std::string("?")) + ")";
            break;
        case TransitionKind::Observation:
            step = "obs";
            beta = "observation '" + std::string(session.Pool().Strings().Get(tr.label)) + "'";
            break;
        case TransitionKind::Action:
            step = std::to_string(trace.StepIndex(t));
            beta = Denotation::ActionAtom(session, tr.action);
            if (tr.status != ActionStatus::Success)
                beta += tr.status == ActionStatus::Failed ? " (failed)" : " (cancelled)";
            break;
        }
        std::string disclosed;
        for (AssertionId a = tr.disclosedBegin; a < tr.disclosedEnd && a < gamma.Size(); a++) {
            if (gamma.Predicate(a) == session.GetSignature().hasName)
                continue; // provenance names are implied by the subject names
            if (!disclosed.empty())
                disclosed += ", ";
            disclosed += Denotation::Atom(session, a);
        }
        if (tr.completionAssertion != INVALID_ASSERTION_ID && tr.completionAssertion < gamma.Size()) {
            if (!disclosed.empty())
                disclosed += ", ";
            disclosed += Denotation::Atom(session, tr.completionAssertion);
        }
        for (AssertionId a = std::max(tr.disclosedEnd, tr.completionAssertion == INVALID_ASSERTION_ID ? 0u : tr.completionAssertion + 1);
             a < tr.toCount && a < gamma.Size();
             a++) {
            if (!disclosed.empty())
                disclosed += ", ";
            disclosed += Denotation::Atom(session, a) + " (derived)";
        }
        text += "| " + step + " | " + beta + " | " + (disclosed.empty() ? std::string("-") : disclosed) + " | " + std::to_string(tr.toCount) + " |\n";
    }
    return text;
}

std::string ExplanationFormatter::ToMarkdown(const Explanation& e, const Interpretation& interpretation)
{
    if (!e.session)
        return "No disclosure session.";
    const auto& session  = *e.session;
    const auto& registry = session.Registry();
    std::string md;
    const std::string rootName = registry.IsValid(e.root) ? registry.Get(e.root).name : std::string("?");
    md += "# HDF explanation: " + rootName + "\n\n";
    md += "## Outcome\n" + e.outcome + "  (|Gamma_n| = " + std::to_string(e.finalState.assertionCount) + ", " + std::to_string(session.Trace().ActionCount()) +
          " action step(s))\n\n";
    md += "## Interpretation\n" + InterpretationStep(e, interpretation) + "\n\n";
    if (e.decision.fromVerdict && e.decision.verdictAssertion < session.Gamma().Size()) {
        const auto& record = session.Derivations().Get(e.decision.verdictAssertion);
        md += "## Verdict assertion\n" + Denotation::Atom(session, e.decision.verdictAssertion) + "  -- " +
              Denotation::Assertion(session, e.decision.verdictAssertion) + "\n";
        if (record.kind == DerivationKind::Rule && record.ruleOrAction < session.GetSpecification().assertionRules.size()) {
            const auto& rule = session.GetSpecification().assertionRules[record.ruleOrAction];
            md += "Rule " + rule.name + ": " + session.GetSpecification().FormatRule(rule, session.GetSignature(), session.Pool()) + "\n";
            if (!rule.explanation.empty())
                md += "Why: " + rule.explanation + "\n";
            md += "Instantiated premises:\n";
            for (const auto premise : session.Derivations().Premises(record))
                md += "  - " + Denotation::Atom(session, premise) + "  -- " + Denotation::Assertion(session, premise) + "\n";
        }
        md += "\n## Derivation tree\n" + DerivationTreeText(session, e.tree) + "\n";
    }
    md += "## Provenance\n";
    if (e.decision.provenancePath.empty()) {
        md += rootName + "\n\n";
    } else {
        // X -> ... -> X' (the path is stored from X' up to X)
        for (size_t i = e.decision.provenancePath.size(); i-- > 0;) {
            md += registry.Get(e.decision.provenancePath[i]).name;
            if (i > 0)
                md += " -> ";
        }
        md += "\n\n";
    }
    md += "## Disclosure trace\n" + TraceTable(session) + "\n";
    md += "## Stop reason\n" + std::string(StopReasonName(e.stopReason)) + "\n";
    return md;
}

} // namespace GView::HDF
