#include "DisclosureSession.hpp"

#include <chrono>

namespace GView::HDF
{
namespace
{
    int64 NowMilliseconds()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }
} // namespace

std::string_view TransitionKindName(TransitionKind kind)
{
    switch (kind) {
    case TransitionKind::InitialExtraction:
        return "initial extraction";
    case TransitionKind::Action:
        return "action";
    case TransitionKind::Observation:
        return "observation";
    }
    return "?";
}

std::string_view StopReasonName(StopReason reason)
{
    switch (reason) {
    case StopReason::None:
        return "none (in progress)";
    case StopReason::Conclusive:
        return "conclusive";
    case StopReason::ManualStop:
        return "manual stop";
    case StopReason::NoSelectableActions:
        return "no selectable actions";
    case StopReason::PolicyLimit:
        return "policy limit";
    }
    return "?";
}

std::string_view StoppingPolicyKindName(StoppingPolicyKind kind)
{
    switch (kind) {
    case StoppingPolicyKind::Conclusive:
        return "conclusive";
    case StoppingPolicyKind::Manual:
        return "manual";
    case StoppingPolicyKind::Exhaustive:
        return "exhaustive";
    }
    return "?";
}

std::optional<StoppingPolicyKind> StoppingPolicyKindFromName(std::string_view name)
{
    if (name == "conclusive")
        return StoppingPolicyKind::Conclusive;
    if (name == "manual")
        return StoppingPolicyKind::Manual;
    if (name == "exhaustive")
        return StoppingPolicyKind::Exhaustive;
    return std::nullopt;
}

std::string_view StepStatusName(StepStatus status)
{
    switch (status) {
    case StepStatus::Executed:
        return "executed";
    case StepStatus::Finished:
        return "the disclosure process is finished";
    case StepStatus::Busy:
        return "another transition is in progress";
    case StepStatus::InvalidAction:
        return "invalid ground action";
    case StepStatus::NotSelectable:
        return "the ground action is not selectable (already completed)";
    case StepStatus::NoExecutor:
        return "no tool can execute this action";
    }
    return "?";
}

uint32 DisclosureTrace::ActionCount() const
{
    uint32 count = 0;
    for (const auto& t : transitions)
        if (t.kind == TransitionKind::Action)
            count++;
    return count;
}

uint32 DisclosureTrace::StepIndex(uint32 transition) const
{
    uint32 count = 0;
    for (uint32 i = 0; i < transition && i < transitions.size(); i++)
        if (transitions[i].kind == TransitionKind::Action)
            count++;
    return count;
}

DisclosureSession::DisclosureSession(
      uint32 sessionIndex,
      const Signature& sig,
      const Specification& spec,
      const Interpretation& interp,
      ConstantPool& constantPool,
      SubjectRegistry& subjects,
      SessionHost* sessionHost,
      StoppingPolicy stoppingPolicy,
      uint32 maxDerivedPerStep)
    : index(sessionIndex), signature(sig), specification(spec), interpretation(interp), pool(constantPool), registry(subjects), host(sessionHost),
      policy(stoppingPolicy), maxDerived(maxDerivedPerStep == 0 ? DEFAULT_MAX_DERIVED : maxDerivedPerStep),
      lastDecision(interp.NotEvaluated(INVALID_SUBJECT_ID))
{
    gamma.Reserve(signature.predicates.Count());
}

ConstantId DisclosureSession::SubjectConstant(SubjectId s) const
{
    return registry.IsValid(s) ? registry.Get(s).constant : INVALID_CONSTANT_ID;
}

bool DisclosureSession::OwnsSubject(SubjectId s) const
{
    return registry.IsValid(s) && registry.Get(s).session == index;
}

bool DisclosureSession::OpenScope(TransitionKind kind, SubjectId subject, StringId label)
{
    if (scope.open) {
        scope.nesting++;
        return false;
    }
    scope                           = Scope{};
    scope.open                      = true;
    scope.transition.kind           = kind;
    scope.transition.subject        = subject;
    scope.transition.label          = label;
    scope.transition.fromCount      = gamma.Size();
    scope.transition.disclosedBegin = gamma.Size();
    return true;
}

void DisclosureSession::CloseScope()
{
    if (!scope.open)
        return;
    auto tr = scope.transition;
    if (tr.kind != TransitionKind::Action)
        tr.disclosedEnd = gamma.Size();
    const auto transitionIndex = trace.Size();
    const bool fireGround      = !groundRulesFired;
    groundRulesFired           = true;
    const auto closure         = AssertionEntailment::Close(gamma, specification, tr.disclosedBegin, derivations, transitionIndex, maxDerived, fireGround);
    if (closure.limitReached) {
        tr.closureIncomplete = 1;
        LOG_ERROR("HDF: MAX_DERIVED_PER_STEP (%u) reached, the closure of transition %u is incomplete", maxDerived, transitionIndex);
    }
    tr.toCount   = gamma.Size();
    tr.timestamp = NowMilliseconds();
    trace.transitions.push_back(tr);
    scope = Scope{};
    if (!hasInitialState && tr.kind == TransitionKind::InitialExtraction && tr.subject == root) {
        initialState    = { tr.toCount };
        hasInitialState = true;
    }
    AfterTransition(transitionIndex);
}

void DisclosureSession::AfterTransition(uint32 transitionIndex)
{
    generation++;
    ActionEntailment::Enabled(gamma, specification, enabledUpTo, enabled);
    enabledUpTo = gamma.Size();
    completed.resize(enabled.Size());
    selectable.clear();
    for (GroundActionId b = 0; b < enabled.Size(); b++) {
        completed[b] = ActionEntailment::IsCompleted(gamma, signature, enabled, b) ? 1 : 0;
        if (!completed[b])
            selectable.push_back(b);
    }
    // pi is evaluated on I(Gamma_i+1, tau_X): a derived verdict assertion is evidence, not a stopping condition
    RefreshDecision();
    if (!finished) {
        std::optional<StopReason> stop;
        if (policy.maxSteps > 0 && trace.ActionCount() >= policy.maxSteps)
            stop = StopReason::PolicyLimit;
        else if (policy.custom)
            stop = policy.custom->ShouldStop(*this, lastDecision);
        else if (policy.kind == StoppingPolicyKind::Conclusive && lastDecision.settled)
            stop = StopReason::Conclusive;
        else if (policy.kind == StoppingPolicyKind::Exhaustive && selectable.empty())
            stop = StopReason::NoSelectableActions;
        if (stop.has_value() && *stop != StopReason::None)
            Finish(*stop);
    }
    if (host)
        host->OnTransition(*this, transitionIndex);
}

bool DisclosureSession::InsertDisclosed(PredicateId p, std::span<const ConstantId> args, StringId expl)
{
    const auto r = gamma.Insert(p, args, expl);
    if (r.id == INVALID_ASSERTION_ID)
        return false;
    if (!r.inserted)
        return true; // set semantics: already known
    const auto transitionIndex = trace.Size();
    switch (scope.transition.kind) {
    case TransitionKind::InitialExtraction:
        derivations.Record(r.id, DerivationKind::InitialExtraction, scope.transition.subject, 0, 0, transitionIndex);
        break;
    case TransitionKind::Observation:
        derivations.Record(r.id, DerivationKind::Observation, scope.transition.label, 0, 0, transitionIndex);
        break;
    case TransitionKind::Action:
        derivations.Record(r.id, DerivationKind::Action, scope.transition.action, scope.premiseOffset, scope.premiseCount, transitionIndex);
        break;
    }
    return true;
}

SubjectId DisclosureSession::BeginRoot(std::string_view name, bool hasContent)
{
    if (root != INVALID_SUBJECT_ID || scope.open)
        return INVALID_SUBJECT_ID;
    root = registry.Create(name, INVALID_SUBJECT_ID, index, hasContent);
    if (root == INVALID_SUBJECT_ID)
        return root;
    auto& entry    = registry.GetMutable(root);
    entry.constant = pool.InternSubject(signature.subjectSort, root);
    OpenScope(TransitionKind::InitialExtraction, root, EMPTY_STRING_ID);
    const ConstantId x = entry.constant;
    const ConstantId nameArgs[2]{ x, pool.InternString(signature.stringSort, registry.Get(root).name) };
    InsertDisclosed(signature.hasName, nameArgs, EMPTY_STRING_ID);
    if (hasContent)
        InsertDisclosed(signature.hasContent, std::span<const ConstantId>(&x, 1), EMPTY_STRING_ID);
    if (host)
        host->OnSubjectCreated(*this, root);
    return root;
}

SubjectId DisclosureSession::CreateSubject(std::string_view name, SubjectId parent, bool hasContent, bool markPending)
{
    if (finished || !scope.open || !OwnsSubject(parent))
        return INVALID_SUBJECT_ID;
    const auto y = registry.Create(name, parent, index, hasContent);
    if (y == INVALID_SUBJECT_ID)
        return y;
    auto& entry        = registry.GetMutable(y);
    entry.constant     = pool.InternSubject(signature.subjectSort, y);
    const ConstantId c = entry.constant;
    const ConstantId provenance[2]{ c, SubjectConstant(parent) };
    InsertDisclosed(signature.extractedFrom, provenance, EMPTY_STRING_ID);
    const ConstantId nameArgs[2]{ c, pool.InternString(signature.stringSort, registry.Get(y).name) };
    InsertDisclosed(signature.hasName, nameArgs, EMPTY_STRING_ID);
    if (hasContent)
        InsertDisclosed(signature.hasContent, std::span<const ConstantId>(&c, 1), EMPTY_STRING_ID);
    if (markPending)
        pendingSubject = y;
    if (host)
        host->OnSubjectCreated(*this, y);
    return y;
}

SubjectId DisclosureSession::BeginChild(std::string_view name, SubjectId parent, bool hasContent)
{
    if (finished || !OwnsSubject(parent))
        return INVALID_SUBJECT_ID;
    if (scope.open) {
        // joins the open transition (e.g. a window opened by an executor without CreateSubject)
        const auto y = CreateSubject(name, parent, hasContent, false);
        if (y != INVALID_SUBJECT_ID)
            scope.nesting++;
        return y;
    }
    OpenScope(TransitionKind::InitialExtraction, INVALID_SUBJECT_ID, EMPTY_STRING_ID);
    const auto y             = CreateSubject(name, parent, hasContent, false);
    scope.transition.subject = y;
    if (y == INVALID_SUBJECT_ID)
        CloseScope();
    return y;
}

void DisclosureSession::BeginInitialExtraction(SubjectId subject)
{
    if (finished && !scope.open)
        return;
    OpenScope(TransitionKind::InitialExtraction, subject, EMPTY_STRING_ID);
}

void DisclosureSession::EndInitialExtraction()
{
    EndObservation();
}

void DisclosureSession::BeginObservation(SubjectId subject, std::string_view label)
{
    if (finished && !scope.open)
        return;
    OpenScope(TransitionKind::Observation, subject, pool.Strings().Intern(label.substr(0, 256)));
}

void DisclosureSession::EndObservation()
{
    if (!scope.open)
        return;
    if (scope.nesting > 0) {
        scope.nesting--;
        return;
    }
    if (stepInProgress)
        return; // the step closes its own scope
    CloseScope();
}

bool DisclosureSession::ConvertArgs(PredicateId p, std::span<const ArgValue> values, ConstantId* out, std::string& error)
{
    const auto& symbol = signature.predicates.Get(p);
    if (values.size() != symbol.arity.size()) {
        error = symbol.name + " expects " + std::to_string(symbol.arity.size()) + " argument(s), got " + std::to_string(values.size());
        return false;
    }
    for (size_t i = 0; i < values.size(); i++) {
        const auto sort = symbol.arity[i].sort;
        if (signature.sorts.Kind(sort) == SortKind::Subject) {
            if (values[i].kind != ArgValue::Kind::Subject || !OwnsSubject(values[i].subject)) {
                error = symbol.name + ": argument '" + symbol.arity[i].name + "' must be a subject of this disclosure session";
                return false;
            }
            out[i] = sort == signature.subjectSort ? SubjectConstant(values[i].subject) : pool.InternSubject(sort, values[i].subject);
            continue;
        }
        const auto c = pool.Intern(sort, values[i]);
        if (!c.has_value()) {
            error = symbol.name + ": argument '" + symbol.arity[i].name + "' is not representable in sort " + std::string(signature.sorts.Name(sort));
            return false;
        }
        out[i] = *c;
    }
    return true;
}

bool DisclosureSession::Disclose(PredicateId p, std::span<const ArgValue> values, std::string_view explanation, std::string* error)
{
    std::string localError;
    std::string& err = error ? *error : localError;
    if (finished) {
        err = "the disclosure process is finished (session frozen)";
        return false;
    }
    if (!signature.predicates.IsValid(p)) {
        err = "unknown predicate";
        return false;
    }
    const auto& symbol = signature.predicates.Get(p);
    if (symbol.isBuiltin || symbol.IsCompletion()) {
        err = "predicate '" + symbol.name + "' is reserved to the engine";
        return false;
    }
    if (host && host->IsPredicateRejected(p)) {
        err = "predicate '" + symbol.name + "' differs between the module and HDF.json (rejected)";
        return false;
    }
    ConstantId args[MAX_ARITY];
    if (!ConvertArgs(p, values, args, err))
        return false;
    const auto expl = explanation.empty() ? EMPTY_STRING_ID : pool.Strings().Intern(explanation.substr(0, MAX_STRING_CONSTANT));
    const std::span<const ConstantId> ground(args, values.size());
    if (scope.open)
        return InsertDisclosed(p, ground, expl);
    // outside any scope: a one-call observation
    SubjectId subject = root;
    for (size_t i = 0; i < values.size(); i++)
        if (values[i].kind == ArgValue::Kind::Subject) {
            subject = values[i].subject;
            break;
        }
    OpenScope(TransitionKind::Observation, subject, pool.Strings().Intern("Disclose"));
    const bool ok = InsertDisclosed(p, ground, expl);
    CloseScope();
    return ok;
}

bool DisclosureSession::AssertGround(PredicateId p, std::span<const ConstantId> args)
{
    if (!scope.open || !signature.predicates.IsValid(p) || args.size() != signature.predicates.Get(p).arity.size())
        return false;
    return InsertDisclosed(p, args, EMPTY_STRING_ID);
}

GroundActionView DisclosureSession::ViewOf(GroundActionId beta) const
{
    GroundActionView view;
    if (beta >= enabled.Size())
        return view;
    const auto& ga = enabled.Get(beta);
    view.action    = ga.action;
    view.name      = signature.actions.Get(ga.action).name;
    view.args      = enabled.Args(beta);
    view.pool      = &pool;
    return view;
}

GroundActionId DisclosureSession::FindSelectable(ActionId action, std::span<const ConstantId> args) const
{
    const auto beta = enabled.Find(action, args);
    if (beta == INVALID_GROUND_ACTION_ID || IsCompleted(beta))
        return INVALID_GROUND_ACTION_ID;
    return beta;
}

StepResult DisclosureSession::Step(GroundActionId beta, const ActionInput* input)
{
    StepResult result;
    if (finished) {
        result.status = StepStatus::Finished;
        return result;
    }
    if (stepInProgress || scope.open) {
        result.status = StepStatus::Busy;
        return result;
    }
    if (beta >= enabled.Size()) {
        result.status = StepStatus::InvalidAction;
        return result;
    }
    if (IsCompleted(beta)) {
        result.status = StepStatus::NotSelectable;
        return result;
    }
    auto* executor = host ? host->ExecutorFor(*this, beta) : nullptr;
    if (!executor) {
        result.status = StepStatus::NoExecutor;
        return result;
    }

    // copy beta (the enabled set is stable during the step, the copy keeps the view independent of it anyway)
    const auto& ga = enabled.Get(beta);
    ConstantId args[MAX_ARITY];
    const auto source = enabled.Args(beta);
    std::copy(source.begin(), source.end(), args);
    const std::span<const ConstantId> ground(args, source.size());
    const auto& action = signature.actions.Get(ga.action);
    SubjectId subject  = root;
    for (const auto c : ground)
        if (pool.Kind(c) == SortKind::Subject) {
            subject = pool.AsSubject(c);
            break;
        }

    OpenScope(TransitionKind::Action, subject, EMPTY_STRING_ID);
    scope.transition.action = beta;
    scope.premiseOffset     = derivations.StorePremises(enabled.Premises(beta));
    scope.premiseCount      = ga.premiseCount;
    stepInProgress          = true;

    GroundActionView view;
    view.action = ga.action;
    view.name   = action.name;
    view.args   = ground;
    view.pool   = &pool;
    DisclosureSink sink(this, Subject{ subject });
    const auto status = executor->Execute(view, input, sink);

    // Gamma_i+1 = Cl_R(Gamma_i u Gamma_beta u D_beta); D_beta = { Done_a(c1..ck) } only for a successful execution
    scope.transition.status       = status;
    scope.transition.disclosedEnd = gamma.Size();
    if (status == ActionStatus::Success && !action.repeatable && action.donePredicate != INVALID_PREDICATE_ID) {
        const auto r = gamma.Insert(action.donePredicate, ground);
        if (r.inserted)
            derivations.Record(r.id, DerivationKind::Completion, beta, scope.premiseOffset, scope.premiseCount, trace.Size());
        scope.transition.completionAssertion = r.id;
    }
    stepInProgress      = false;
    pendingSubject      = INVALID_SUBJECT_ID;
    scope.nesting       = 0;
    result.status       = StepStatus::Executed;
    result.actionStatus = status;
    result.transition   = trace.Size();
    CloseScope();
    return result;
}

void DisclosureSession::RefreshDecision()
{
    if (!registry.IsValid(root))
        return;
    lastDecision  = interpretation.Interpret(gamma, signature, pool, registry, root, static_cast<uint32>(selectable.size()));
    decisionValid = true;
}

void DisclosureSession::Finish(StopReason reason)
{
    if (finished)
        return;
    finished   = true;
    stopReason = reason;
    // the final state is reported (a manual stop between transitions sees the same Gamma, the refresh is cheap)
    RefreshDecision();
    generation++;
}

DisclosureResult DisclosureSession::Result() const
{
    return { State(), &trace, stopReason };
}

KnowledgeState DisclosureSession::StateAfter(uint32 transition) const
{
    if (transition >= trace.Size())
        return State();
    return { trace.transitions[transition].toCount };
}

} // namespace GView::HDF
