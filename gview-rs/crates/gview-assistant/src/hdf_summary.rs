//! HDF analysis summary (`SummaryController.cpp`; spec §5).
//!
//! The only LLM path that honours `RestrictedMode` (`LLMHints`).
//!
//! ```text
//! Knowledge state (Gamma):
//! - <fact line>
//!
//! Available actions:
//! - <action>: <message>
//!
//! Provide a brief analysis summary and list recommended actions prefixed with 'ACTION:'.
//! ```
//!
//! The rule engine that produces facts and suggestions is ported by
//! the `hdf-knowledge-base` task; this module takes the already
//! formatted fact lines (`FormatFactMessage`) and the `(action name,
//! suggestion message)` pairs (`GetActName` + `sug.message`) as a
//! [`KnowledgeState`].

use gview_security::restricted_mode::RestrictedMode;

use crate::AskFn;

/// `displayPrompt` of the summary request.
pub const HDF_SUMMARY_DISPLAY_PROMPT: &str = "HDF Analysis Summary";
/// First prompt line.
pub const KNOWLEDGE_STATE_HEADER: &str = "Knowledge state (Gamma):\n";
/// Actions header (preceded by a blank line).
pub const AVAILABLE_ACTIONS_HEADER: &str = "\nAvailable actions:\n";
/// Closing instruction (preceded by a blank line).
pub const SUMMARY_INSTRUCTION: &str =
    "\nProvide a brief analysis summary and list recommended actions prefixed with 'ACTION:'.\n";
/// Prefix that marks a recommended action line in the answer.
pub const ACTION_PREFIX: &str = "ACTION:";

/// One action suggestion (`Suggestion` result of type `Action`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuggestedAction {
    /// `engine.GetActName(res.data.action_id)`.
    pub action: String,
    /// `sug.message`.
    pub message: String,
}

/// The serialized inputs of `SerializeKnowledgeState`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KnowledgeState {
    /// `FormatFactMessage(fact, spec)` for every fact whose predicate
    /// has a specification (facts without one are skipped by the
    /// caller, as in C++).
    pub facts: Vec<String>,
    /// One entry per `Action` result of every suggestion.
    pub actions: Vec<SuggestedAction>,
}

/// `SerializeKnowledgeState`.
#[must_use]
pub fn serialize_knowledge_state(state: &KnowledgeState) -> String {
    let mut out = String::from(KNOWLEDGE_STATE_HEADER);
    for fact in &state.facts {
        out.push_str("- ");
        out.push_str(fact);
        out.push('\n');
    }
    out.push_str(AVAILABLE_ACTIONS_HEADER);
    for action in &state.actions {
        out.push_str("- ");
        out.push_str(&action.action);
        out.push_str(": ");
        out.push_str(&action.message);
        out.push('\n');
    }
    out.push_str(SUMMARY_INSTRUCTION);
    out
}

/// C++ `SummaryResult`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SummaryResult {
    /// `AskSmartAssistant`'s `isSuccess` (parse-only: non-empty text).
    pub success: bool,
    /// The whole answer.
    pub narrative: String,
    /// Text after `ACTION:` on each such line, leading spaces removed.
    pub recommended_actions: Vec<String>,
}

/// `ParseAssistantResponse`: the full text becomes `narrative`; every
/// line **longer** than `ACTION:` that starts with it contributes its
/// remainder (leading spaces stripped, empty remainders dropped).
#[must_use]
pub fn parse_assistant_response(response: &str) -> SummaryResult {
    let mut result = SummaryResult {
        success: !response.is_empty(),
        narrative: response.to_owned(),
        recommended_actions: Vec::new(),
    };
    for line in response.split('\n') {
        if line.len() > ACTION_PREFIX.len() {
            if let Some(rest) = line.strip_prefix(ACTION_PREFIX) {
                let name = rest.trim_start_matches(' ');
                if !name.is_empty() {
                    result.recommended_actions.push(name.to_owned());
                }
            }
        }
    }
    result
}

/// `RequestSummary`.
///
/// Empty result without an assistant or when `RestrictedMode` is
/// active with `LLMHints` disabled; otherwise the serialized state is
/// sent and the answer parsed. `ask` receives `(prompt,
/// display_prompt)` like `AskSmartAssistant`; a failed call still
/// yields its failure text as `narrative` with `success == false`
/// (C++ overwrites `parsed.success` with the call status).
pub fn request_summary(
    state: &KnowledgeState,
    restricted: &RestrictedMode,
    ask: Option<AskFn<'_>>,
) -> SummaryResult {
    let Some(ask) = ask else {
        return SummaryResult::default();
    };
    if !restricted.llm_hints_allowed() {
        return SummaryResult::default();
    }
    let prompt = serialize_knowledge_state(state);
    let (response, success) = match ask(&prompt, HDF_SUMMARY_DISPLAY_PROMPT) {
        Ok(text) => (text, true),
        Err(err) => (err.message, false),
    };
    let mut parsed = parse_assistant_response(&response);
    parsed.success = success;
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AssistantError;
    use gview_security::restricted_mode::{Feature, Policy};

    fn sample_state() -> KnowledgeState {
        KnowledgeState {
            facts: vec!["file has high entropy".to_owned(), "imports VirtualAlloc".to_owned()],
            actions: vec![
                SuggestedAction {
                    action: "unpack".to_owned(),
                    message: "packed section detected".to_owned(),
                },
                SuggestedAction {
                    action: "scan".to_owned(),
                    message: "suspicious import".to_owned(),
                },
            ],
        }
    }

    #[test]
    fn serialization_matches_cpp_layout() {
        assert_eq!(
            serialize_knowledge_state(&sample_state()),
            "Knowledge state (Gamma):\n- file has high entropy\n- imports VirtualAlloc\n\nAvailable actions:\n- unpack: packed section detected\n- scan: suspicious import\n\nProvide a brief analysis summary and list recommended actions prefixed with 'ACTION:'.\n"
        );
        assert_eq!(
            serialize_knowledge_state(&KnowledgeState::default()),
            "Knowledge state (Gamma):\n\nAvailable actions:\n\nProvide a brief analysis summary and list recommended actions prefixed with 'ACTION:'.\n"
        );
    }

    #[test]
    fn hdf_action_prefix() {
        let text = "Summary line.\nACTION: unpack\nACTION:   scan the file\nACTION:\nACTION:  \n ACTION: indented\nAction: lower\nACTION:x";
        let parsed = parse_assistant_response(text);
        assert!(parsed.success);
        assert_eq!(parsed.narrative, text);
        assert_eq!(parsed.recommended_actions, vec!["unpack", "scan the file", "x"]);
        let empty = parse_assistant_response("");
        assert!(!empty.success);
        assert!(empty.recommended_actions.is_empty());
        // Exactly the prefix (no remainder) is not an action.
        assert!(parse_assistant_response("ACTION:").recommended_actions.is_empty());
    }

    fn policy_disabling_llm() -> Policy {
        let mut policy = Policy::default();
        policy.disabled_features = vec![Feature::LlmHints];
        policy
    }

    #[test]
    fn llm_hints_gate() {
        let mode = RestrictedMode::default();
        let calls = std::cell::Cell::new(0u32);
        let mut ask = |prompt: &str, display: &str| -> Result<String, AssistantError> {
            calls.set(calls.get().saturating_add(1));
            assert_eq!(display, "HDF Analysis Summary");
            assert!(prompt.starts_with("Knowledge state (Gamma):\n"));
            Ok("Narrative\nACTION: unpack".to_owned())
        };
        let result = request_summary(&sample_state(), &mode, Some(&mut ask));
        assert!(result.success);
        assert_eq!(result.recommended_actions, vec!["unpack"]);
        assert_eq!(calls.get(), 1);

        mode.activate(policy_disabling_llm(), 0).expect("activate");
        assert!(!mode.llm_hints_allowed());
        let result = request_summary(&sample_state(), &mode, Some(&mut ask));
        assert_eq!(result, SummaryResult::default());
        assert_eq!(calls.get(), 1, "no call while restricted");

        mode.deactivate();
        let result = request_summary(&sample_state(), &mode, Some(&mut ask));
        assert!(result.success);
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn no_assistant_or_failed_call() {
        let mode = RestrictedMode::default();
        assert_eq!(request_summary(&sample_state(), &mode, None), SummaryResult::default());
        let mut failing =
            |_: &str, _: &str| -> Result<String, AssistantError> { Err(AssistantError::new("Error calling Gemini API!")) };
        let result = request_summary(&sample_state(), &mode, Some(&mut failing));
        assert!(!result.success);
        assert_eq!(result.narrative, "Error calling Gemini API!");
        assert!(result.recommended_actions.is_empty());
    }
}
