#pragma once

// E: the explanation of an outcome: the interpretation decision, the derivation tree of the verdict assertion that was
// used, the provenance path X' -> .. -> X, the disclosure trace and the stop reason; rendered by ExplanationFormatter.
// Denotations den(gamma) / den(beta) are rendered from the templates of the signature.

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
    DerivationTree tree; // DT of decision.verdictAssertion (empty when the outcome is the fallback)
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
    // the interpretation step: "max over 1 assertion(s) = 0.75; 0.75 >= 0.70 => Malicious"
    static std::string InterpretationStep(const Explanation& explanation, const Interpretation& interpretation);
    // | step | beta_i | Gamma_beta_i | |Gamma_i+1| | table of the trace (markdown)
    static std::string TraceTable(const DisclosureSession& session);
};

} // namespace GView::HDF
