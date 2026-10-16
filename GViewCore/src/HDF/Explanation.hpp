#pragma once

// E: the explanation of an outcome. Conclusive: the label, per clause of the winning condition the satisfying assertion
// (combined score + DT) or the statement that no such assertion exists, the per-subject outcomes of X and of the deciding
// Y, the provenance path X -> .. -> Y. Inconclusive: the reason (no label satisfied: the first failed clause of every
// label; conflict: the labels in conflict) and the core-level stop reason. Rendered by ExplanationFormatter; denotations
// den(gamma) / den(beta) are rendered from the templates of the signature.

#include "DisclosureSession.hpp"
#include "Interpretation.hpp"

namespace GView::HDF
{
class Denotation
{
  public:
    // a constant as text: subjects by name, strings as-is, reals with %.2f
    static std::string Constant(const ConstantPool& pool, const SubjectRegistry& registry, ConstantId c);
    static std::string Render(
          const DenotationTemplate& den,
          std::string_view symbolName,
          std::span<const ConstantId> args,
          const ConstantPool& pool,
          const SubjectRegistry& registry);
    // den(gamma) (falls back to "P(c1, .., ck)" when the predicate has no denotation)
    static std::string Assertion(const DisclosureSession& session, AssertionId id);
    // "P(c1, .., ck)"
    static std::string Atom(const DisclosureSession& session, AssertionId id);
    // den(beta)
    static std::string Action(const DisclosureSession& session, GroundActionId beta);
    // "<a>(c1, .., ck)"
    static std::string ActionAtom(const DisclosureSession& session, GroundActionId beta);
    // where an assertion comes from: "rule R", "action <a>(..) (step i)", "initial extraction", ...
    static std::string Source(const DisclosureSession& session, AssertionId id);
};

struct Explanation {
    const DisclosureSession* session{ nullptr };
    SubjectId root{ INVALID_SUBJECT_ID };
    InterpretationDecision decision;
    std::string outcome;
    // one DT per present clause of the winning label of the deciding subject (empty when Inconclusive)
    std::vector<std::pair<AssertionId, DerivationTree>> witnesses;
    StopReason stopReason{ StopReason::None };
    KnowledgeState finalState;

    static Explanation Build(const DisclosureSession& session, const Interpretation& interpretation, SubjectId root);
};

class ExplanationFormatter
{
  public:
    static std::string ToMarkdown(const Explanation& explanation, const Interpretation& interpretation);
    // indented textual DT
    static std::string DerivationTreeText(const DisclosureSession& session, const DerivationTree& tree);
    // the interpretation step: I_subj of X (and of the deciding Y), then one line per clause of the winning condition
    // ("HasMaliciousness(Y, .) = max{0.75} = 0.75 >= 0.70 [holds]"), or the reason of Inconclusive
    static std::string InterpretationStep(const Explanation& explanation, const Interpretation& interpretation);
    // one clause of a label evaluated for one subject
    static std::string ClauseText(
          const DisclosureSession& session,
          const Interpretation& interpretation,
          const SubjectDecision& subject,
          const Clause& clause,
          const ClauseEvaluation& eval);
    // "Malicious (conclusive, via payload.exe)", "Inconclusive (no label satisfied)", "Inconclusive (conflict: Malicious, Benign)"
    static std::string DecisionSummary(const InterpretationDecision& decision, const Interpretation& interpretation, const SubjectRegistry& registry);
    // | step | beta_i | Gamma_beta_i | |Gamma_i+1| | table of the trace (markdown)
    static std::string TraceTable(const DisclosureSession& session);
};

} // namespace GView::HDF
