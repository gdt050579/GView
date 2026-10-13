#pragma once

// One disclosure process (X, H) -> (Gamma_n, tau_X, sigma) per input subject X. The session owns Gamma (AssertionBase),
// the derivation records, the trace and the incrementally maintained Enabled set; every subject extracted from X (and
// their windows) discloses into the same session.

#include "DisclosureTrace.hpp"
#include "Entailment.hpp"
#include "SubjectRegistry.hpp"

namespace GView::HDF
{
enum class StopReason : uint8 { None = 0, VerdictReached, ManualStop, NoSelectableActions, PolicyLimit };
std::string_view StopReasonName(StopReason reason);

// pi: when the process stops by itself. A verdict assertion is always reported; it stops the process only when
// stopOnVerdict is set (the default in GView is to let the analyst decide).
struct StoppingPolicy {
    bool stopOnVerdict{ false };
    uint32 maxSteps{ 0 }; // 0 = unlimited
};

class DisclosureSession;

// (Gamma_n, tau_X, sigma)
struct DisclosureResult {
    KnowledgeState finalState;
    const DisclosureTrace* trace{ nullptr };
    StopReason stopReason{ StopReason::None };
};

enum class StepStatus : uint8 { Executed = 0, Finished, Busy, InvalidAction, NotSelectable, NoExecutor };
std::string_view StepStatusName(StepStatus status);

struct StepResult {
    StepStatus status{ StepStatus::InvalidAction };
    ActionStatus actionStatus{ ActionStatus::Failed };
    uint32 transition{ INVALID_INDEX };
};

// the environment of a session: the tool T (executors) and the observers (Engine at runtime, a fixture in tests)
struct SessionHost {
    virtual ActionExecutorInterface* ExecutorFor(const DisclosureSession& session, GroundActionId beta) = 0;
    virtual void OnTransition([[maybe_unused]] DisclosureSession& session, [[maybe_unused]] uint32 transition)
    {
    }
    virtual void OnSubjectCreated([[maybe_unused]] DisclosureSession& session, [[maybe_unused]] SubjectId subject)
    {
    }
    // runtime drift check: disclosures on this predicate are rejected (arity/sort mismatch between a module and HDF.json)
    virtual bool IsPredicateRejected([[maybe_unused]] PredicateId p) const
    {
        return false;
    }
    virtual ~SessionHost() = default;
};

class DisclosureSession
{
    const uint32 index;
    const Signature& signature;
    const Specification& specification;
    ConstantPool& pool;
    SubjectRegistry& registry;
    SessionHost* host;
    StoppingPolicy policy;
    uint32 maxDerived;

    AssertionBase gamma;
    DerivationIndex derivations;
    DisclosureTrace trace;
    GroundActionSet enabled;
    std::vector<uint8> completed; // per beta of enabled
    std::vector<GroundActionId> selectable;
    uint32 enabledUpTo{ 0 }; // Enabled has been computed for Gamma[0, enabledUpTo)
    uint64 generation{ 0 };

    struct Scope {
        DisclosureTransition transition;
        uint32 nesting{ 0 };
        uint32 premiseOffset{ 0 };
        uint8 premiseCount{ 0 };
        bool open{ false };
    } scope;

    SubjectId root{ INVALID_SUBJECT_ID };
    SubjectId pendingSubject{ INVALID_SUBJECT_ID }; // created by the running step, waiting for its window
    KnowledgeState initialState;                    // Gamma_0
    StopReason stopReason{ StopReason::None };
    bool stepInProgress{ false };
    bool finished{ false };
    bool verdictReached{ false };
    bool groundRulesFired{ false };
    bool hasInitialState{ false };

    bool OpenScope(TransitionKind kind, SubjectId subject, StringId label);
    void CloseScope();
    void AfterTransition(uint32 transitionIndex);
    bool InsertDisclosed(PredicateId p, std::span<const ConstantId> args, StringId expl);
    bool ConvertArgs(PredicateId p, std::span<const ArgValue> values, ConstantId* out, std::string& error);

  public:
    DisclosureSession(
          uint32 index,
          const Signature& signature,
          const Specification& specification,
          ConstantPool& pool,
          SubjectRegistry& registry,
          SessionHost* host,
          StoppingPolicy policy,
          uint32 maxDerivedPerStep);
    DisclosureSession(const DisclosureSession&)            = delete;
    DisclosureSession& operator=(const DisclosureSession&) = delete;

    // --- subjects ------------------------------------------------------------------------------------------------
    // the input subject X (opens the initial extraction scope; HasName(X, name) and HasContent(X) are part of Init_T(X))
    SubjectId BeginRoot(std::string_view name, bool hasContent);
    // a fresh subject y with ExtractedFrom(y, parent), HasName(y, name) (+ HasContent(y)); requires an open scope
    SubjectId CreateSubject(std::string_view name, SubjectId parent, bool hasContent, bool markPending);
    // a subject opened from parent outside of the pending-subject protocol (the analyst opened an item): opens Init_T(y)
    // (or joins the open transition); close it with EndInitialExtraction
    SubjectId BeginChild(std::string_view name, SubjectId parent, bool hasContent);
    // the subject of the open transition (INVALID_SUBJECT_ID when no scope is open)
    inline SubjectId ScopeSubject() const
    {
        return scope.open ? scope.transition.subject : INVALID_SUBJECT_ID;
    }
    inline SubjectId Root() const
    {
        return root;
    }
    inline SubjectId PendingSubject() const
    {
        return pendingSubject;
    }
    inline void ConsumePendingSubject()
    {
        pendingSubject = INVALID_SUBJECT_ID;
    }
    ConstantId SubjectConstant(SubjectId s) const;
    bool OwnsSubject(SubjectId s) const;

    // --- scopes (transitions that are not selected actions) -----------------------------------------------------
    // Init_T(subject); nested calls inside an open scope are no-ops (the facts join the open transition)
    void BeginInitialExtraction(SubjectId subject);
    void EndInitialExtraction();
    void BeginObservation(SubjectId subject, std::string_view label);
    void EndObservation();
    inline bool IsScopeOpen() const
    {
        return scope.open;
    }

    // --- disclosure ------------------------------------------------------------------------------------------------
    // asserts p(args) about the current scope (a one-call observation is opened when no scope is open)
    bool Disclose(PredicateId p, std::span<const ArgValue> args, std::string_view explanation, std::string* error = nullptr);
    bool Disclose(PredicateId p, std::initializer_list<ArgValue> args, std::string_view explanation = {}, std::string* error = nullptr)
    {
        return Disclose(p, std::span<const ArgValue>(args.begin(), args.size()), explanation, error);
    }

    // engine-internal: inserts a ground assertion (built-ins allowed) into the open scope
    bool AssertGround(PredicateId p, std::span<const ConstantId> args);

    // --- the disclosure step Gamma_i ->beta_i Gamma_i+1 ---------------------------------------------------------
    StepResult Step(GroundActionId beta, const ActionInput* input = nullptr);
    GroundActionId FindSelectable(ActionId action, std::span<const ConstantId> args) const;
    void Finish(StopReason reason);

    // --- read-only views -------------------------------------------------------------------------------------------
    inline uint32 Index() const
    {
        return index;
    }
    inline const AssertionBase& Gamma() const
    {
        return gamma;
    }
    inline const DerivationIndex& Derivations() const
    {
        return derivations;
    }
    inline const DisclosureTrace& Trace() const
    {
        return trace;
    }
    inline const GroundActionSet& Enabled() const
    {
        return enabled;
    }
    inline std::span<const GroundActionId> Selectable() const
    {
        return selectable;
    }
    inline bool IsCompleted(GroundActionId beta) const
    {
        return beta < completed.size() && completed[beta] != 0;
    }
    inline KnowledgeState State() const
    {
        return { gamma.Size() };
    }
    inline KnowledgeState InitialState() const
    {
        return initialState;
    }
    inline bool HasInitialState() const
    {
        return hasInitialState;
    }
    inline bool IsFinished() const
    {
        return finished;
    }
    inline bool IsStepInProgress() const
    {
        return stepInProgress;
    }
    inline bool VerdictReached() const
    {
        return verdictReached;
    }
    // a verdict assertion was reached (reported; the process continues unless the policy says otherwise)
    inline bool ShouldStop() const
    {
        return finished || verdictReached;
    }
    inline StopReason GetStopReason() const
    {
        return stopReason;
    }
    inline uint64 Generation() const
    {
        return generation;
    }
    inline const StoppingPolicy& Policy() const
    {
        return policy;
    }
    DisclosureResult Result() const;
    // Gamma_i: the knowledge state after transition t
    KnowledgeState StateAfter(uint32 transition) const;

    inline const Signature& GetSignature() const
    {
        return signature;
    }
    inline const Specification& GetSpecification() const
    {
        return specification;
    }
    inline const ConstantPool& Pool() const
    {
        return pool;
    }
    inline const SubjectRegistry& Registry() const
    {
        return registry;
    }
    GroundActionView ViewOf(GroundActionId beta) const;
};

} // namespace GView::HDF
