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
    e.session  = &session;
    e.root     = root;
    e.decision = interpretation.Interpret(
          session.Gamma(), session.GetSignature(), session.Pool(), session.Registry(), root, static_cast<uint32>(session.Selectable().size()));
    e.outcome    = std::string(interpretation.outcomes.Label(e.decision.outcome));
    e.stopReason = session.GetStopReason();
    e.finalState = session.State();
    if (!e.decision.conclusive)
        return e;
    // the witnesses: the strongest assertion of every present clause of the winning label, for the deciding subject
    const auto* deciding  = e.decision.FindSubject(e.decision.deciding);
    const auto* condition = interpretation.ConditionOf(e.decision.outcome.index);
    const auto* label     = deciding ? deciding->FindLabel(e.decision.outcome.index) : nullptr;
    if (!condition || !label)
        return e;
    for (const auto& eval : label->clauses) {
        if (eval.clause >= condition->clauses.size() || condition->clauses[eval.clause].kind != ClauseKind::Present)
            continue;
        if (!eval.present || eval.witness >= session.Gamma().Size())
            continue;
        bool known = false;
        for (const auto& [a, tree] : e.witnesses)
            known |= a == eval.witness;
        if (!known)
            e.witnesses.emplace_back(eval.witness, DerivationTree::Build(session.Derivations(), eval.witness));
    }
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

namespace
{
    constexpr size_t MAX_SCORES_SHOWN   = 8;
    constexpr size_t MAX_SUBJECTS_SHOWN = 32;

    std::string Number(double value)
    {
        char text[64];
        snprintf(text, sizeof(text), "%.2f", value);
        return text;
    }

    std::string SubjectName(const SubjectRegistry& registry, SubjectId s)
    {
        return registry.IsValid(s) ? registry.Get(s).name : std::string("?");
    }

    // "max{0.75, 0.60} = 0.75": the combined score of (V, Y) with the raw scores in Gamma order
    std::string Combined(const DisclosureSession& session, const SubjectDecision& subject, PredicateId p)
    {
        const auto* score = subject.FindScore(p);
        if (!score)
            return "?";
        std::string text(AggregateFunctionName(score->aggregate));
        text += "{";
        const auto& registry = session.Registry();
        const auto c         = registry.IsValid(subject.subject) ? registry.Get(subject.subject).constant : INVALID_CONSTANT_ID;
        size_t shown         = 0;
        if (c != INVALID_CONSTANT_ID) {
            for (const auto a : session.Gamma().WithPredicateAndFirst(p, c)) {
                const auto args = session.Gamma().Args(a);
                if (args.size() != 2)
                    continue;
                if (shown == MAX_SCORES_SHOWN) {
                    text += ", ...";
                    break;
                }
                text += (shown > 0 ? ", " : "") + Number(session.Pool().AsReal(args[1]));
                shown++;
            }
        }
        return text + "} = " + Number(score->score);
    }

    std::string LabelList(const Interpretation& interpretation, std::span<const uint8> labels)
    {
        std::string text;
        for (const auto l : labels)
            text += (text.empty() ? "" : ", ") + std::string(interpretation.outcomes.Label({ l }));
        return text;
    }

    // "I_subj(Y) = <label>" (+ the reason when Inconclusive)
    std::string SubjectOutcome(const Interpretation& interpretation, const SubjectRegistry& registry, const SubjectDecision& d)
    {
        std::string text = "I_subj(" + SubjectName(registry, d.subject) + ") = " + std::string(interpretation.outcomes.Label(d.outcome));
        if (!interpretation.outcomes.IsConclusive(d.outcome))
            text += " (" + std::string(InconclusiveReasonName(d.reason)) + ")";
        return text;
    }

    // "  <Label> holds for Y:" + one line per clause
    std::string HoldingCondition(
          const DisclosureSession& session, const Interpretation& interpretation, const SubjectDecision& subject, const LabelCondition& condition)
    {
        const auto* label = subject.FindLabel(condition.outcome);
        if (!label)
            return {};
        std::string text =
              std::string(interpretation.outcomes.Label({ condition.outcome })) + " holds for " + SubjectName(session.Registry(), subject.subject) + ":\n";
        for (const auto& eval : label->clauses)
            if (eval.clause < condition.clauses.size())
                text += "  " + ExplanationFormatter::ClauseText(session, interpretation, subject, condition.clauses[eval.clause], eval) + "\n";
        return text;
    }
} // namespace

std::string ExplanationFormatter::ClauseText(
      const DisclosureSession& session,
      [[maybe_unused]] const Interpretation& interpretation,
      const SubjectDecision& subject,
      const Clause& clause,
      const ClauseEvaluation& eval)
{
    const auto& predicates = session.GetSignature().predicates;
    const std::string name = predicates.IsValid(clause.predicate) ? predicates.Get(clause.predicate).name : std::string("?");
    const std::string y    = SubjectName(session.Registry(), subject.subject);
    const std::string op   = std::string(ComparisonOperatorName(clause.op)) + " " + Number(clause.threshold);
    if (clause.kind == ClauseKind::Present) {
        if (!eval.present)
            return name + "(" + y + ", .) missing [fails]";
        const std::string value = name + "(" + y + ", .) = " + Combined(session, subject, clause.predicate);
        return eval.holds ? value + " " + op + " [holds]" : value + ", not " + op + " [fails]";
    }
    const std::string statement = "no " + name + "(" + y + ", c) with c " + op;
    if (!eval.present)
        return statement + " [holds: no assertion]";
    if (eval.holds)
        return statement + " [holds: " + Combined(session, subject, clause.predicate) + ", not " + op + "]";
    return statement + " [fails: " + name + "(" + y + ", .) = " + Combined(session, subject, clause.predicate) + " " + op + " present]";
}

std::string ExplanationFormatter::DecisionSummary(const InterpretationDecision& d, const Interpretation& interpretation, const SubjectRegistry& registry)
{
    std::string text(interpretation.outcomes.Label(d.outcome));
    if (d.conclusive) {
        if (!d.settled)
            text += " (provisional, settles at exhaustion: " + std::to_string(d.selectableCount) + " selectable action(s) remain";
        else if (d.settle == SettleMode::Exhaustion)
            text += " (conclusive, settled: no selectable action remains";
        else
            text += " (conclusive";
        if (d.deciding != d.input && registry.IsValid(d.deciding))
            text += ", via " + registry.Get(d.deciding).name;
        return text + ")";
    }
    if (d.reason == InconclusiveReason::Conflict)
        return text + " (conflict: " + LabelList(interpretation, d.conflictingLabels) + ")";
    return text + " (" + std::string(InconclusiveReasonName(d.reason)) + ")";
}

std::string ExplanationFormatter::InterpretationStep(const Explanation& e, const Interpretation& interpretation)
{
    const auto& d = e.decision;
    if (!e.session)
        return "no disclosure session";
    const auto& session  = *e.session;
    const auto& registry = session.Registry();
    const auto* x        = d.FindSubject(d.input);
    if (!x)
        return "I(" + SubjectName(registry, d.input) + ") = " + e.outcome + " (" + std::string(InconclusiveReasonName(d.reason)) +
               ")\ncore stop reason: " + std::string(StopReasonName(e.stopReason));

    std::string text = SubjectOutcome(interpretation, registry, *x) + "\n";
    const auto* y    = d.FindSubject(d.deciding);
    if (d.conclusive) {
        if (y && y != x) {
            // X -> ... -> Y (the path is stored from Y up to X)
            std::string along;
            for (size_t i = d.provenancePath.size(); i-- > 0;)
                along += SubjectName(registry, d.provenancePath[i]) + (i > 0 ? " -> " : "");
            text += SubjectOutcome(interpretation, registry, *y) + ", propagated to " + SubjectName(registry, d.input) + " along " + along + "\n";
        }
        if (const auto* condition = interpretation.ConditionOf(d.outcome.index); condition && y)
            text += HoldingCondition(session, interpretation, *y, *condition);
        text += "=> " + e.outcome + " (aggregation over subjects: " + std::string(SubjectAggregationKindName(interpretation.aggregation)) + ")";
        // a label that settles at exhaustion is final only when nothing is selectable (an action may still disclose the
        // evidence one of its absence clauses excludes)
        if (!d.settled)
            text += "\n" + e.outcome + " holds but is not settled: it settles at exhaustion and " + std::to_string(d.selectableCount) +
                    " selectable action(s) remain";
        else if (d.settle == SettleMode::Exhaustion)
            text += "\nsettled: no selectable action remains (" + e.outcome + " settles at exhaustion)";
        return text;
    }

    if (d.reason == InconclusiveReason::Conflict) {
        text += "reason: conflict (" + LabelList(interpretation, d.conflictingLabels) + ")";
        if (y && y != x)
            text += " on " + SubjectName(registry, y->subject) + " (" + std::string(SubjectAggregationKindName(interpretation.aggregation)) +
                    " aggregation over subjects)";
        text += "\n";
        // every label in conflict with the first subject (pre-order) it holds for
        for (const auto l : d.conflictingLabels) {
            const auto* condition = interpretation.ConditionOf(l);
            if (!condition)
                continue;
            for (const auto& s : d.subjects)
                if (const auto* label = s.FindLabel(l); label && label->holds) {
                    text += HoldingCondition(session, interpretation, s, *condition);
                    break;
                }
        }
    } else {
        text += "reason: " + std::string(InconclusiveReasonName(d.reason)) + "\n";
        // the first failed clause of every label: for X, and for every subject of the tree when the label propagates (it
        // would hold for X if it held for any of them)
        for (const auto& condition : interpretation.labels) {
            const std::string name(interpretation.outcomes.Label({ condition.outcome }));
            const bool perSubject = condition.propagate && d.subjects.size() > 1;
            if (perSubject)
                text += "  " + name + " (propagating) fails for all " + std::to_string(d.subjects.size()) + " subjects of the provenance tree:\n";
            size_t shown = 0;
            for (const auto& s : d.subjects) {
                if (!perSubject && &s != x)
                    continue;
                const auto* label = s.FindLabel(condition.outcome);
                if (!label || label->firstFailedClause < 0 || static_cast<size_t>(label->firstFailedClause) >= label->clauses.size())
                    continue;
                const auto& eval = label->clauses[label->firstFailedClause];
                if (eval.clause >= condition.clauses.size())
                    continue;
                if (shown == MAX_SUBJECTS_SHOWN) {
                    text += "    ... (" + std::to_string(d.subjects.size() - shown) + " more)\n";
                    break;
                }
                text += (perSubject ? "    " : "  " + name + ": ") + ClauseText(session, interpretation, s, condition.clauses[eval.clause], eval) + "\n";
                shown++;
            }
        }
        if (interpretation.labels.empty())
            text += "  (the specification declares no label condition)\n";
    }
    text += "core stop reason: " + std::string(StopReasonName(e.stopReason));
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
    if (!e.witnesses.empty()) {
        md += "## Verdict assertions\n";
        for (const auto& [a, tree] : e.witnesses) {
            const auto& record = session.Derivations().Get(a);
            md += Denotation::Atom(session, a) + "  -- " + Denotation::Assertion(session, a) + "\n";
            if (record.kind == DerivationKind::Rule && record.ruleOrAction < session.GetSpecification().assertionRules.size()) {
                const auto& rule = session.GetSpecification().assertionRules[record.ruleOrAction];
                md += "Rule " + rule.name + ": " + session.GetSpecification().FormatRule(rule, session.GetSignature(), session.Pool()) + "\n";
                if (!rule.explanation.empty())
                    md += "Why: " + rule.explanation + "\n";
                md += "Instantiated premises:\n";
                for (const auto premise : session.Derivations().Premises(record))
                    md += "  - " + Denotation::Atom(session, premise) + "  -- " + Denotation::Assertion(session, premise) + "\n";
            } else {
                md += "Source: " + Denotation::Source(session, a) + "\n";
            }
            md += "\n";
        }
        md += "## Derivation trees\n";
        for (const auto& [a, tree] : e.witnesses)
            md += Denotation::Atom(session, a) + "\n" + DerivationTreeText(session, tree) + "\n";
    }
    md += "## Provenance\n";
    if (e.decision.provenancePath.empty()) {
        md += rootName + "\n\n";
    } else {
        // X -> ... -> Y (the path is stored from Y up to X)
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
