//! Smart-assistant queries from the disassembly viewer: Ctrl+K
//! (function name), Ctrl+L (MITRE techniques) and the `Assistant`
//! context-menu entries.
//!
//! C++ anchors: `Instance::QuerySmartAssistant` (`Instance.cpp:
//! 1585-1681`, the selection / zone pre-checks and the per-query
//! parameters), `Instance::QuerySmartAssistantX86X64`
//! (`DissasmX86.cpp:2015-2229`, the line walk, the API call and the
//! result dispatch), `DissasmKeyEvents.cpp:310-325` (menu ids) and
//! `Config.hpp:36-40, 71-76`. Spec `06_SMART_ASSISTANT` §4,
//! `APPCUI_RS_UI_AND_ASYNC_GUIDE` §5.2.
//!
//! Split into pure steps so the shell owns every dialog and the
//! background worker:
//!
//! 1. [`query_for_key_response`] / [`query_for_menu_command`] map the
//!    key or menu id to a [`DisasmQueryType`];
//! 2. [`plan_query`] runs the C++ pre-checks over the zones, cursor
//!    and selection and yields a [`QueryPlan`] or the verbatim
//!    message-box text ([`QueryRefusal`]);
//! 3. [`run_query`] walks the zone through an [`AsmLineSource`],
//!    builds the prompt with `gview_assistant::disasm_prompt`, calls
//!    the assistant (any `FnMut(prompt, display) -> Result`, so the
//!    shell can run it on a `BackgroundTask`) and parses the answer
//!    into a [`QueryOutcome`];
//! 4. [`plan_comment_application`] computes the *Apply* step of the
//!    `ExplainCode` dialog.
//!
//! After a query the C++ clears `asmPreCacheData`; the shell does the
//! same on its pre-cache once it applied the outcome.

use gview_assistant::disasm_parse::{
    extract_decompiled_code, merge_comment, parse_comments_zone, FunctionNameOutcome, CODE_EXPLANATION_TITLE,
    MITRE_TECHNIQUES_TITLE, NAME_SELECTOR_TITLE, NO_COMMENTS_FOUND_WARNING, NO_RESULT_PREFIX,
    UNEXPECTED_COMMENTS_WARNING,
};
use gview_assistant::disasm_prompt::{
    self, AsmLine, CollectedLines, DisasmQueryType, PromptError, QueryParams, FUNCTION_NAMES_TO_REQUEST,
    MAX_DISSASM_LINES_ANALYSED, NO_INSTRUCTIONS_FOUND, SELECTION_REQUIRED_WARNING,
};
use gview_assistant::AskFn;
use gview_core::selection::Selection;

use super::input::{zones_from_line_position, CursorDissasm, DissasmKeyResponse};
use super::zone::{DisassemblyLanguage, ZoneEntry};

/// One `Assistant` context-menu entry (`Config.hpp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssistantMenuCommand {
    /// `RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_*` id.
    pub id: i32,
    /// Menu caption.
    pub label: &'static str,
    /// Query it triggers.
    pub query: DisasmQueryType,
}

/// `RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_NAME_FUNCTION`.
pub const MENU_QUERY_NAME_FUNCTION: i32 = 11;
/// `RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_EXPLAIN_CODE`.
pub const MENU_QUERY_EXPLAIN_CODE: i32 = 12;
/// `RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_CONVERT_HIGH_LEVEL`.
pub const MENU_QUERY_CONVERT_HIGH_LEVEL: i32 = 13;
/// `RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_FN_NAME_AND_EXPLANATION`.
pub const MENU_QUERY_FN_NAME_AND_EXPLANATION: i32 = 14;
/// `RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_MITRE_TECHNIQUES`.
pub const MENU_QUERY_MITRE_TECHNIQUES: i32 = 15;

/// The `Assistant` sub-menu (`Config.hpp:71-76`), in menu order.
pub const ASSISTANT_MENU_COMMANDS: [AssistantMenuCommand; 5] = [
    AssistantMenuCommand {
        id: MENU_QUERY_NAME_FUNCTION,
        label: "Ask appropriate name function",
        query: DisasmQueryType::FunctionName,
    },
    AssistantMenuCommand {
        id: MENU_QUERY_EXPLAIN_CODE,
        label: "Explain the code in selection",
        query: DisasmQueryType::ExplainCode,
    },
    AssistantMenuCommand {
        id: MENU_QUERY_CONVERT_HIGH_LEVEL,
        label: "Convert selection code to a higher form",
        query: DisasmQueryType::ConvertToHighLevel,
    },
    AssistantMenuCommand {
        id: MENU_QUERY_FN_NAME_AND_EXPLANATION,
        label: "Ask for name and small explanation",
        query: DisasmQueryType::FunctionNameAndExplanation,
    },
    AssistantMenuCommand {
        id: MENU_QUERY_MITRE_TECHNIQUES,
        label: "Ask for MITRE techniques",
        query: DisasmQueryType::MitreTechniques,
    },
];

/// Sub-menu caption.
pub const ASSISTANT_MENU_NAME: &str = "Assistant";

/// `DissasmKeyEvents.cpp:310-325`: context-menu id → query.
#[must_use]
pub fn query_for_menu_command(id: i32) -> Option<DisasmQueryType> {
    ASSISTANT_MENU_COMMANDS.iter().find(|c| c.id == id).map(|c| c.query)
}

/// Ctrl+K / Ctrl+L (`COMMAND_QUERY_FUNCTION_NAME`,
/// `COMMAND_QUERY_MITRE_TECHNIQUE`) → query.
#[must_use]
pub const fn query_for_key_response(response: DissasmKeyResponse) -> Option<DisasmQueryType> {
    match response {
        DissasmKeyResponse::QueryFunctionName => Some(DisasmQueryType::FunctionName),
        DissasmKeyResponse::QueryMitreTechnique => Some(DisasmQueryType::MitreTechniques),
        _ => None,
    }
}

/// Which `MessageBox` the C++ shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeKind {
    /// `ShowNotification("Warning", …)`.
    Warning,
    /// `ShowNotification("Error", …)`.
    Error,
}

/// A pre-check failure of `Instance::QuerySmartAssistant`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryRefusal {
    /// Box title.
    pub kind: NoticeKind,
    /// Verbatim text.
    pub message: &'static str,
}

/// `"Please make a selection on a single zone!"`.
pub const SINGLE_ZONE_ERROR: &str = "Please make a selection on a single zone!";
/// `"Please make a selection on an expanded zone!"`.
pub const EXPANDED_ZONE_ERROR: &str = "Please make a selection on an expanded zone!";
/// `"Please do not select the title in the collapsible zones!"`.
pub const TITLE_LINE_WARNING: &str = "Please do not select the title in the collapsible zones!";
/// `"Please make a selection on a dissasm zone!"`.
pub const DISSASM_ZONE_ERROR: &str = "Please make a selection on a dissasm zone!";
/// `"Query function name available only for x86 and x64 functions!"`.
pub const X86_ONLY_ERROR: &str = "Query function name available only for x86 and x64 functions!";
/// Lines the zone spends on its title and menu row
/// (`assert(line >= 2); line -= 2`).
pub const ZONE_HEADER_LINES: u32 = 2;

/// Everything `QuerySmartAssistantX86X64` needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryPlan {
    /// The query kind.
    pub query: DisasmQueryType,
    /// Its verbatim parameters.
    pub params: QueryParams,
    /// Index into `parseZones` of the single code zone hit.
    pub zone_index: u32,
    /// Zone-relative line of the cursor / selection start **after**
    /// the `-= 2` header adjustment (the line `GetCurrentAsmLine`
    /// receives for the `sub_` gate).
    pub line: u32,
}

/// `Instance::QuerySmartAssistant` pre-checks. `text_size` is
/// `Layout.textSize` (selection offsets are `line * textSize +
/// column`, `OffsetToLinePosition`).
///
/// # Errors
///
/// The C++ message box text and kind, in C++ order: selection
/// required, single zone, expanded zone, title line, code zone,
/// x86/x64 language.
pub fn plan_query(
    query: DisasmQueryType,
    zones: &[ZoneEntry],
    cursor: CursorDissasm,
    selection: &Selection,
    text_size: u32,
) -> Result<QueryPlan, QueryRefusal> {
    let (line_start, line_end) = if query.requires_selection() {
        let Some((start, end)) = selection.get_selection(0) else {
            return Err(QueryRefusal {
                kind: NoticeKind::Warning,
                message: SELECTION_REQUIRED_WARNING,
            });
        };
        (offset_to_line(start, text_size), offset_to_line(end, text_size))
    } else {
        (cursor.to_line_position().line, 0)
    };

    let zones_found = zones_from_line_position(zones, line_start, line_end);
    let (Some(location), 1) = (zones_found.first(), zones_found.len()) else {
        return Err(QueryRefusal {
            kind: NoticeKind::Error,
            message: SINGLE_ZONE_ERROR,
        });
    };
    let Some(zone) = zones.get(location.zone_index as usize) else {
        return Err(QueryRefusal {
            kind: NoticeKind::Error,
            message: SINGLE_ZONE_ERROR,
        });
    };
    if zone.header().is_collapsed {
        return Err(QueryRefusal {
            kind: NoticeKind::Error,
            message: EXPANDED_ZONE_ERROR,
        });
    }
    if location.starting_line <= 1 {
        return Err(QueryRefusal {
            kind: NoticeKind::Warning,
            message: TITLE_LINE_WARNING,
        });
    }
    let ZoneEntry::Code(code) = zone else {
        return Err(QueryRefusal {
            kind: NoticeKind::Error,
            message: DISSASM_ZONE_ERROR,
        });
    };
    if !matches!(
        code.zone_details.language,
        DisassemblyLanguage::X86 | DisassemblyLanguage::X64
    ) {
        return Err(QueryRefusal {
            kind: NoticeKind::Error,
            message: X86_ONLY_ERROR,
        });
    }
    Ok(QueryPlan {
        query,
        params: query.params(),
        zone_index: location.zone_index,
        line: location.starting_line.saturating_sub(ZONE_HEADER_LINES),
    })
}

/// `OffsetToLinePosition(offset).line` (`Instance.cpp:1205-1208`);
/// a zero `textSize` (C++ would divide by zero) maps to line 0.
#[must_use]
pub fn offset_to_line(offset: u64, text_size: u32) -> u32 {
    offset
        .checked_div(u64::from(text_size))
        .map_or(0, |line| u32::try_from(line).unwrap_or(u32::MAX))
}

/// One zone line as `GetCurrentAsmLine` returns it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtractedAsmLine {
    /// Instruction byte length; `0` for annotation / name lines.
    pub size: u32,
    /// Mnemonic, or the annotation text for `size == 0` lines.
    pub mnemonic: String,
    /// Operand string; `None` where the C++ `op_str` pointer is null
    /// (annotation lines).
    pub op_str: Option<String>,
}

/// What the viewer host provides for one code zone.
///
/// C++ `DissasmCodeZone::GetCurrentAsmLine` / `GetComment` and the
/// zone's line bounds. Lines are zone-relative *dissasm* lines as the
/// C++ walk counts them (`currentDissasmLine`).
pub trait AsmLineSource {
    /// `GetCurrentAsmLine(line)`; `None` where the C++ would assert.
    fn asm_line(&mut self, line: u32) -> Option<ExtractedAsmLine>;

    /// `GetComment(line)`.
    fn comment(&self, line: u32) -> Option<String>;

    /// `zone->startLineIndex`.
    fn start_line_index(&self) -> u32;

    /// `zone->endingLineIndex`.
    fn ending_line_index(&self) -> u32;
}

/// Failures of [`run_query`] (all shown as `"Warning"` boxes except
/// [`QueryFailure::NoAssistant`], whose message the registry already
/// showed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryFailure {
    /// The cursor line does not start with `sub_`; carries the
    /// verbatim warning.
    NotFunctionStart(&'static str),
    /// `GetSmartAssistantInterface()` returned null — silent return.
    NoAssistant,
    /// The walk produced no listing line.
    NoInstructions,
    /// The assistant call failed; carries the failure text.
    AssistantFailed(String),
    /// The source could not provide a line the C++ asserts on.
    LineUnavailable(u32),
}

impl QueryFailure {
    /// The `MessageBox` text, `None` for the silent
    /// [`QueryFailure::NoAssistant`].
    #[must_use]
    pub fn notice(&self) -> Option<String> {
        match self {
            Self::NotFunctionStart(text) => Some((*text).to_owned()),
            Self::NoAssistant => None,
            Self::NoInstructions | Self::LineUnavailable(_) => Some(NO_INSTRUCTIONS_FOUND.to_owned()),
            Self::AssistantFailed(text) => Some(format!("{NO_RESULT_PREFIX}{text}")),
        }
    }
}

impl core::fmt::Display for QueryFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.notice() {
            Some(text) => f.write_str(&text),
            None => f.write_str("no smart assistant available"),
        }
    }
}

impl std::error::Error for QueryFailure {}

/// Parsed answer, ready for the shell's dialogs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryOutcome {
    /// `QueryFunctionNameDialog`; on *Apply* the shell renames `line`
    /// with [`FunctionNameOutcome::rename_target`].
    FunctionName {
        /// Text shown as the user's question.
        display_prompt: String,
        /// Names to list and the rename lookup.
        names: FunctionNameOutcome,
        /// Zone-relative line to rename (`TryRenameLine(line, …)`).
        line: u32,
    },
    /// `QueryShowCodeDialog(result, "Code explanation", false, true)`;
    /// on *Apply* use [`plan_comment_application`].
    ExplainCode {
        /// Text shown as the user's question.
        display_prompt: String,
        /// Full answer.
        response: String,
        /// `(instruction, comment)` pairs after `CommentsZoneExplained`.
        comments: Vec<(String, String)>,
        /// The plan's line (comments apply from `line + 1`).
        line: u32,
    },
    /// `QueryShowCodeDialog(result, "Code explanation", true, false)`;
    /// on *Open* the shell opens `decompiled` as `temp_decompile.cpp`.
    ConvertToHighLevel {
        /// Text shown as the user's question.
        display_prompt: String,
        /// Full answer.
        response: String,
        /// Extracted code, `None` disables the *Open* button.
        decompiled: Option<String>,
    },
    /// `QueryShowCodeDialog(result, "MITRE techniques", false, false)`.
    MitreTechniques {
        /// Text shown as the user's question.
        display_prompt: String,
        /// Full answer.
        response: String,
    },
    /// `QueryShowCodeDialog(result, "Code explanation", false, true)`.
    FunctionNameAndExplanation {
        /// Text shown as the user's question.
        display_prompt: String,
        /// Full answer.
        response: String,
    },
}

impl QueryOutcome {
    /// Dialog title the C++ uses for this outcome.
    #[must_use]
    pub const fn dialog_title(&self) -> &'static str {
        match self {
            Self::FunctionName { .. } => NAME_SELECTOR_TITLE,
            Self::MitreTechniques { .. } => MITRE_TECHNIQUES_TITLE,
            Self::ExplainCode { .. } | Self::ConvertToHighLevel { .. } | Self::FunctionNameAndExplanation { .. } => {
                CODE_EXPLANATION_TITLE
            }
        }
    }

    /// The display prompt of any outcome.
    #[must_use]
    pub fn display_prompt(&self) -> &str {
        match self {
            Self::FunctionName { display_prompt, .. }
            | Self::ExplainCode { display_prompt, .. }
            | Self::ConvertToHighLevel { display_prompt, .. }
            | Self::MitreTechniques { display_prompt, .. }
            | Self::FunctionNameAndExplanation { display_prompt, .. } => display_prompt,
        }
    }
}

/// `DissasmX86.cpp:2043-2082`: gathers the lines after `line` (at
/// most [`MAX_DISSASM_LINES_ANALYSED`], stopping at the zone end) and
/// applies the send / API-call caps and the `ret` stop.
pub fn collect_zone_lines(params: &QueryParams, source: &mut dyn AsmLineSource, line: u32) -> CollectedLines {
    let ending = source.ending_line_index();
    let mut actual_line_in_document = line
        .saturating_add(source.start_line_index())
        .saturating_add(1);
    let mut current_dissasm_line = line.saturating_add(1);
    let mut gathered: Vec<(ExtractedAsmLine, Option<String>)> = Vec::new();
    while actual_line_in_document < ending && (gathered.len() as u32) < MAX_DISSASM_LINES_ANALYSED {
        let Some(extracted) = source.asm_line(current_dissasm_line) else {
            break;
        };
        let comment = if params.include_comments {
            source.comment(current_dissasm_line)
        } else {
            None
        };
        gathered.push((extracted, comment));
        actual_line_in_document = actual_line_in_document.saturating_add(1);
        current_dissasm_line = current_dissasm_line.saturating_add(1);
    }
    let lines = gathered.iter().map(|(l, c)| AsmLine {
        size: l.size,
        mnemonic: &l.mnemonic,
        op_str: l.op_str.as_deref().unwrap_or(""),
        comment: c.as_deref(),
    });
    disasm_prompt::collect_lines(params, lines)
}

/// `Instance::QuerySmartAssistantX86X64` up to the dialogs.
///
/// `prompt_retries` is `GetPromptRetriesCount()` (`FunctionName` asks
/// that many times; `0` sends once and shows no names, like the C++
/// `while (retriesNumber)` loop).
///
/// # Errors
///
/// See [`QueryFailure`]; the shell shows [`QueryFailure::notice`].
pub fn run_query(
    plan: &QueryPlan,
    source: &mut dyn AsmLineSource,
    ask: Option<AskFn<'_>>,
    prompt_retries: u32,
) -> Result<QueryOutcome, QueryFailure> {
    let params = &plan.params;
    let display_prompt = if params.mnemonic_starts_with.is_empty() {
        params.display_prompt.to_owned()
    } else {
        let cursor_line = source
            .asm_line(plan.line)
            .ok_or(QueryFailure::LineUnavailable(plan.line))?;
        disasm_prompt::display_prompt(params, &cursor_line.mnemonic).map_err(map_prompt_error)?
    };

    let Some(ask) = ask else {
        return Err(QueryFailure::NoAssistant);
    };

    let collected = collect_zone_lines(params, source, plan.line);
    let prompt = disasm_prompt::assemble_prompt(params, &collected).map_err(map_prompt_error)?;
    let first = ask(&prompt, &display_prompt).map_err(|e| QueryFailure::AssistantFailed(e.message))?;

    Ok(match plan.query {
        DisasmQueryType::FunctionName => {
            let mut responses: Vec<String> = Vec::new();
            let mut retries = prompt_retries;
            let mut result = first;
            while retries > 0 {
                responses.push(result);
                retries = retries.saturating_sub(1);
                if retries == 0 {
                    break;
                }
                result = ask(&prompt, &display_prompt).map_err(|e| QueryFailure::AssistantFailed(e.message))?;
            }
            QueryOutcome::FunctionName {
                display_prompt,
                names: FunctionNameOutcome::from_responses(&responses, FUNCTION_NAMES_TO_REQUEST as usize),
                line: plan.line,
            }
        }
        DisasmQueryType::ExplainCode => QueryOutcome::ExplainCode {
            display_prompt,
            comments: parse_comments_zone(&first),
            response: first,
            line: plan.line,
        },
        DisasmQueryType::ConvertToHighLevel => QueryOutcome::ConvertToHighLevel {
            display_prompt,
            decompiled: extract_decompiled_code(&first),
            response: first,
        },
        DisasmQueryType::MitreTechniques => QueryOutcome::MitreTechniques {
            display_prompt,
            response: first,
        },
        DisasmQueryType::FunctionNameAndExplanation => QueryOutcome::FunctionNameAndExplanation {
            display_prompt,
            response: first,
        },
    })
}

const fn map_prompt_error(error: PromptError) -> QueryFailure {
    match error {
        PromptError::NotFunctionStart(text) => QueryFailure::NotFunctionStart(text),
        PromptError::NoInstructions => QueryFailure::NoInstructions,
    }
}

/// The *Apply* step of the `ExplainCode` dialog
/// (`DissasmX86.cpp:2166-2202`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommentApplication {
    /// `(zone line, merged comment)` for `AddOrUpdateComment`, in
    /// order.
    pub updates: Vec<(u32, String)>,
    /// Warning boxes to show (verbatim), in order.
    pub warnings: Vec<&'static str>,
    /// The walk ran past the zone end (C++ returns mid-loop; the
    /// updates gathered so far were already applied).
    pub aborted: bool,
    /// Whether the C++ reached `selection.Clear()`.
    pub clear_selection: bool,
}

/// Computes the comment updates for `comments` starting at
/// `line + 1`: instruction lines (`op_str` present) receive the next
/// comment, merged with any existing one as `"<new>; <old>"`.
pub fn plan_comment_application(
    source: &mut dyn AsmLineSource,
    line: u32,
    comments: &[(String, String)],
) -> CommentApplication {
    let mut plan = CommentApplication::default();
    let Some((first_instruction, _)) = comments.first() else {
        plan.warnings.push(NO_COMMENTS_FOUND_WARNING);
        return plan;
    };
    let mut current = line.saturating_add(1);
    let initial = source.asm_line(current).filter(|l| l.size > 0);
    let Some(initial) = initial else {
        plan.warnings.push(NO_INSTRUCTIONS_FOUND);
        return plan;
    };
    let expected = format!("{} {}", initial.mnemonic, initial.op_str.as_deref().unwrap_or(""));
    if *first_instruction != expected {
        plan.warnings.push(UNEXPECTED_COMMENTS_WARNING);
    }
    let ending = source.ending_line_index();
    for (_, comment) in comments {
        loop {
            if source.asm_line(current).is_some_and(|l| l.op_str.is_some()) {
                break;
            }
            current = current.saturating_add(1);
            if current >= ending {
                plan.aborted = true;
                return plan;
            }
        }
        let merged = merge_comment(comment, source.comment(current).as_deref());
        plan.updates.push((current, merged));
        current = current.saturating_add(1);
    }
    plan.clear_selection = true;
    plan
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use gview_assistant::AssistantError;
    use crate::dissasm_viewer::zone::{CollapsibleAndTextZone, DissasmCodeZone};
    use gview_assistant::disasm_prompt::{EXPLAIN_CODE_PROMPT, FUNCTION_NAME_PROMPT, MAX_BYTE_TO_SEND};
    use gview_assistant::gpt4o::{self, Gpt4oAssistant};
    use gview_assistant::http::RecordingTransport;
    use gview_assistant::SmartAssistantProvider;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct MockSource {
        lines: Vec<ExtractedAsmLine>,
        comments: HashMap<u32, String>,
        start: u32,
        ending: u32,
    }

    impl AsmLineSource for MockSource {
        fn asm_line(&mut self, line: u32) -> Option<ExtractedAsmLine> {
            self.lines.get(line as usize).cloned()
        }
        fn comment(&self, line: u32) -> Option<String> {
            self.comments.get(&line).cloned()
        }
        fn start_line_index(&self) -> u32 {
            self.start
        }
        fn ending_line_index(&self) -> u32 {
            self.ending
        }
    }

    fn insn(mnemonic: &str, op_str: &str) -> ExtractedAsmLine {
        ExtractedAsmLine {
            size: 2,
            mnemonic: mnemonic.to_owned(),
            op_str: Some(op_str.to_owned()),
        }
    }

    fn label(text: &str) -> ExtractedAsmLine {
        ExtractedAsmLine {
            size: 0,
            mnemonic: text.to_owned(),
            op_str: None,
        }
    }

    /// A function of `body_len` instructions behind a `sub_` label at
    /// line 0 (the cursor line after the `-2` adjustment).
    fn function_source(body_len: usize) -> MockSource {
        let mut lines = vec![label("sub_401000")];
        for i in 0..body_len {
            lines.push(insn("mov", &format!("eax, {i}")));
        }
        let ending = lines.len() as u32 + 10;
        MockSource {
            lines,
            comments: HashMap::new(),
            start: 0,
            ending,
        }
    }

    fn code_zone(start: u32, end: u32, collapsed: bool, language: DisassemblyLanguage) -> ZoneEntry {
        let mut zone = DissasmCodeZone::default();
        zone.zone.start_line_index = start;
        zone.zone.ending_line_index = end;
        zone.zone.is_collapsed = collapsed;
        zone.zone_details.language = language;
        ZoneEntry::Code(Box::new(zone))
    }

    fn cursor_at(line: u32) -> CursorDissasm {
        CursorDissasm {
            start_view_line: 0,
            line_in_view: line,
            offset: 0,
            has_moved_view: false,
        }
    }

    fn plan_at(query: DisasmQueryType, line: u32) -> QueryPlan {
        QueryPlan {
            query,
            params: query.params(),
            zone_index: 0,
            line,
        }
    }

    #[test]
    fn key_and_menu_mapping() {
        assert_eq!(
            query_for_key_response(DissasmKeyResponse::QueryFunctionName),
            Some(DisasmQueryType::FunctionName)
        );
        assert_eq!(
            query_for_key_response(DissasmKeyResponse::QueryMitreTechnique),
            Some(DisasmQueryType::MitreTechniques)
        );
        assert_eq!(query_for_key_response(DissasmKeyResponse::Handled), None);
        assert_eq!(query_for_menu_command(11), Some(DisasmQueryType::FunctionName));
        assert_eq!(query_for_menu_command(12), Some(DisasmQueryType::ExplainCode));
        assert_eq!(query_for_menu_command(13), Some(DisasmQueryType::ConvertToHighLevel));
        assert_eq!(query_for_menu_command(14), Some(DisasmQueryType::FunctionNameAndExplanation));
        assert_eq!(query_for_menu_command(15), Some(DisasmQueryType::MitreTechniques));
        assert_eq!(query_for_menu_command(10), None);
        let labels: Vec<&str> = ASSISTANT_MENU_COMMANDS.iter().map(|c| c.label).collect();
        assert_eq!(
            labels,
            vec![
                "Ask appropriate name function",
                "Explain the code in selection",
                "Convert selection code to a higher form",
                "Ask for name and small explanation",
                "Ask for MITRE techniques"
            ]
        );
        assert_eq!(ASSISTANT_MENU_NAME, "Assistant");
    }

    #[test]
    fn plan_query_prechecks_in_cpp_order() {
        let zones = vec![
            code_zone(0, 50, false, DisassemblyLanguage::X64),
            ZoneEntry::CollapsibleAndText(CollapsibleAndTextZone {
                zone: {
                    let mut z = CollapsibleAndTextZone::default().zone;
                    z.start_line_index = 50;
                    z.ending_line_index = 60;
                    z
                },
                ..CollapsibleAndTextZone::default()
            }),
            code_zone(60, 70, true, DisassemblyLanguage::X64),
            code_zone(70, 80, false, DisassemblyLanguage::JavaByteCode),
        ];
        let selection = Selection::new();

        // Cursor on line 10 of the x64 zone → line 8 after the header.
        let plan = plan_query(DisasmQueryType::FunctionName, &zones, cursor_at(10), &selection, 80).expect("plan");
        assert_eq!((plan.zone_index, plan.line), (0, 8));
        assert_eq!(plan.params, DisasmQueryType::FunctionName.params());

        // Title / menu rows.
        for line in [0, 1] {
            assert_eq!(
                plan_query(DisasmQueryType::MitreTechniques, &zones, cursor_at(line), &selection, 80),
                Err(QueryRefusal {
                    kind: NoticeKind::Warning,
                    message: TITLE_LINE_WARNING
                })
            );
        }
        // Text zone.
        assert_eq!(
            plan_query(DisasmQueryType::MitreTechniques, &zones, cursor_at(55), &selection, 80).map_err(|r| r.message),
            Err(DISSASM_ZONE_ERROR)
        );
        // Collapsed zone (checked before the title line).
        assert_eq!(
            plan_query(DisasmQueryType::MitreTechniques, &zones, cursor_at(61), &selection, 80).map_err(|r| r.message),
            Err(EXPANDED_ZONE_ERROR)
        );
        // Non-x86 language.
        assert_eq!(
            plan_query(DisasmQueryType::MitreTechniques, &zones, cursor_at(75), &selection, 80).map_err(|r| r.message),
            Err(X86_ONLY_ERROR)
        );
        // Outside every zone.
        assert_eq!(
            plan_query(DisasmQueryType::MitreTechniques, &zones, cursor_at(500), &selection, 80).map_err(|r| r.message),
            Err(SINGLE_ZONE_ERROR)
        );
    }

    #[test]
    fn plan_query_selection_rules() {
        let zones = vec![
            code_zone(0, 50, false, DisassemblyLanguage::X86),
            code_zone(50, 100, false, DisassemblyLanguage::X86),
        ];
        let mut selection = Selection::new();
        let text_size = 80u32;

        // ExplainCode needs a selection.
        assert_eq!(
            plan_query(DisasmQueryType::ExplainCode, &zones, cursor_at(10), &selection, text_size),
            Err(QueryRefusal {
                kind: NoticeKind::Warning,
                message: SELECTION_REQUIRED_WARNING
            })
        );
        // Selection lines 5..=9 of zone 0.
        selection.set_selection(0, 5 * u64::from(text_size), 9 * u64::from(text_size) + 3);
        let plan = plan_query(DisasmQueryType::ConvertToHighLevel, &zones, cursor_at(0), &selection, text_size)
            .expect("plan");
        assert_eq!((plan.zone_index, plan.line), (0, 3));
        // A selection across two zones is refused.
        selection.set_selection(0, 40 * u64::from(text_size), 60 * u64::from(text_size));
        assert_eq!(
            plan_query(DisasmQueryType::ExplainCode, &zones, cursor_at(0), &selection, text_size).map_err(|r| r.message),
            Err(SINGLE_ZONE_ERROR)
        );
        assert_eq!(offset_to_line(160, 80), 2);
        assert_eq!(offset_to_line(160, 0), 0);
    }

    #[test]
    fn mock_api_receives_formatted_prompt_with_100_line_cap() {
        let transport = Arc::new(RecordingTransport::responding(
            r#"{"choices":[{"message":{"content":"decode, parse, init, run, stop"}}]}"#,
        ));
        let mut gpt = Gpt4oAssistant::new(Arc::clone(&transport));
        gpt.receive_config_token("sk-test");
        let mut ask = |prompt: &str, display: &str| gpt.ask(prompt, display);

        let mut source = function_source(130);
        let plan = plan_at(DisasmQueryType::FunctionName, 0);
        let outcome = run_query(&plan, &mut source, Some(&mut ask), 1).expect("outcome");

        let QueryOutcome::FunctionName {
            display_prompt,
            names,
            line,
        } = outcome
        else {
            panic!("function-name outcome expected");
        };
        assert_eq!(display_prompt, "Give me an appropriate name for the function: sub_401000");
        assert_eq!(line, 0);
        assert_eq!(names.shown, vec!["decode", "parse", "init", "run", "stop"]);
        assert_eq!(names.rename_target(2), Some("init"));

        let request = transport.last_request().expect("request sent");
        assert_eq!(request.url, gpt4o::GPT4O_URL);
        let body: serde_json::Value = serde_json::from_str(&request.body).expect("json body");
        let sent = body["messages"][1]["content"].as_str().expect("user content");
        let expected_head = format!("{FUNCTION_NAME_PROMPT}Here is x86 assembly code: \n");
        assert!(sent.starts_with(&expected_head));
        assert_eq!(sent.matches("   mov eax, ").count(), 100, "100-line cap");
        assert!(sent.contains("   mov eax, 0\n"));
        assert!(sent.contains("   mov eax, 99\n"));
        assert!(!sent.contains("   mov eax, 100\n"));
        assert!(!sent.contains("The function also makes these API calls"));
        // Parity: the LocalString<640> grows, nothing is truncated.
        assert!(sent.len() > MAX_BYTE_TO_SEND);
        assert!(sent.ends_with('\n'));
        assert!(!request.body.contains("sub_401000"), "display prompt never leaves the UI");
    }

    #[test]
    fn overflow_calls_and_ret_stop() {
        let mut source = function_source(0);
        source.lines.extend((0..100).map(|i| insn("nop", &format!("{i}"))));
        source.lines.extend((0..12).map(|i| insn("call", &format!("api{i}"))));
        source.lines.push(insn("ret", ""));
        source.lines.push(insn("nop", "after"));
        source.ending = source.lines.len() as u32 + 1;

        let mut sent = Vec::new();
        let mut ask = |prompt: &str, _: &str| {
            sent.push(prompt.to_owned());
            Ok("T1059".to_owned())
        };
        let plan = plan_at(DisasmQueryType::MitreTechniques, 0);
        let outcome = run_query(&plan, &mut source, Some(&mut ask), 1).expect("outcome");
        assert_eq!(
            outcome,
            QueryOutcome::MitreTechniques {
                display_prompt: DisasmQueryType::MitreTechniques.params().display_prompt.to_owned(),
                response: "T1059".to_owned()
            }
        );
        assert_eq!(outcome.dialog_title(), "MITRE techniques");
        let prompt = sent.first().expect("one call");
        assert!(prompt.contains("The function also makes these API calls:    call api0\n"));
        assert_eq!(prompt.matches("   call api").count(), 10);
        assert!(!prompt.contains("after"), "walk stopped at ret");
    }

    #[test]
    fn walk_respects_zone_end_and_150_lines() {
        let mut source = function_source(300);
        source.ending = 41; // start 0 → only lines 1..=39 are inside
        let params = DisasmQueryType::ExplainCode.params();
        assert_eq!(collect_zone_lines(&params, &mut source, 0).assembly.len(), 40);
        source.ending = 1000;
        let collected = collect_zone_lines(&params, &mut source, 0);
        assert_eq!(collected.assembly.len(), 100);
        assert!(collected.api_calls.is_empty());
    }

    #[test]
    fn sub_gate_and_failures() {
        let mut source = function_source(3);
        source.lines[0] = insn("mov", "eax, ebx");
        let plan = plan_at(DisasmQueryType::FunctionName, 0);
        let mut never = |_: &str, _: &str| -> Result<String, AssistantError> { panic!("must not be called") };
        let err = run_query(&plan, &mut source, Some(&mut never), 1).expect_err("gate");
        assert!(matches!(err, QueryFailure::NotFunctionStart(_)));
        assert_eq!(
            err.notice().as_deref(),
            Some("This is not a function start! Please select a \"sub\" instruction! If they are not available please enable DeepScanning.")
        );

        let mut source = function_source(3);
        assert_eq!(run_query(&plan, &mut source, None, 1), Err(QueryFailure::NoAssistant));
        assert_eq!(QueryFailure::NoAssistant.notice(), None);

        let mut empty = function_source(0);
        empty.ending = 1;
        let mut ask = |_: &str, _: &str| Ok(String::new());
        assert_eq!(run_query(&plan, &mut empty, Some(&mut ask), 1), Err(QueryFailure::NoInstructions));
        assert_eq!(QueryFailure::NoInstructions.notice().as_deref(), Some("No instructions found!"));

        let mut source = function_source(3);
        let mut failing = |_: &str, _: &str| Err(AssistantError::new("Error calling Gemini API!"));
        let err = run_query(&plan, &mut source, Some(&mut failing), 1).expect_err("failure");
        assert_eq!(
            err.notice().as_deref(),
            Some("The assistant did not provide a result: Error calling Gemini API!")
        );
        assert_eq!(err.to_string(), "The assistant did not provide a result: Error calling Gemini API!");
        assert_eq!(
            run_query(&plan, &mut MockSource { lines: vec![], comments: HashMap::new(), start: 0, ending: 5 }, Some(&mut ask), 1),
            Err(QueryFailure::LineUnavailable(0))
        );
    }

    #[test]
    fn function_name_retries_and_zero_retries() {
        let mut source = function_source(3);
        let plan = plan_at(DisasmQueryType::FunctionName, 0);
        let answers = ["a, b", "b, c", "c, d"];
        let mut calls = 0usize;
        let mut ask = |_: &str, _: &str| {
            let answer = answers[calls.min(2)].to_owned();
            calls += 1;
            Ok(answer)
        };
        let outcome = run_query(&plan, &mut source, Some(&mut ask), 3).expect("outcome");
        let QueryOutcome::FunctionName { names, .. } = outcome else {
            panic!("function-name outcome expected");
        };
        assert_eq!(calls, 3);
        assert_eq!(names.shown, vec!["b", "c", "a", "d"]);
        assert_eq!(names.last_response_names, vec!["c", "d"]);

        let mut calls = 0usize;
        let mut ask = |_: &str, _: &str| {
            calls += 1;
            Ok("x, y".to_owned())
        };
        let outcome = run_query(&plan, &mut source, Some(&mut ask), 0).expect("outcome");
        let QueryOutcome::FunctionName { names, .. } = outcome else {
            panic!("function-name outcome expected");
        };
        assert_eq!(calls, 1, "the first call always happens");
        assert!(names.shown.is_empty() && names.last_response_names.is_empty());
    }

    #[test]
    fn explain_and_decompile_outcomes() {
        let mut source = function_source(2);
        source.lines[0] = insn("push", "ebp");
        let mut ask = |_: &str, _: &str| {
            Ok("Text\nCommentsZoneExplained\nmov eax, 0 # zero\nmov eax, 1 # one\n".to_owned())
        };
        let plan = plan_at(DisasmQueryType::ExplainCode, 0);
        let outcome = run_query(&plan, &mut source, Some(&mut ask), 1).expect("outcome");
        assert_eq!(outcome.dialog_title(), "Code explanation");
        assert_eq!(outcome.display_prompt(), "Explain the selected code");
        let QueryOutcome::ExplainCode { comments, line, .. } = &outcome else {
            panic!("explain outcome expected");
        };
        assert_eq!(*line, 0);
        assert_eq!(comments.len(), 2);

        let mut ask = |prompt: &str, _: &str| {
            assert!(prompt.starts_with(EXPLAIN_CODE_PROMPT) || prompt.contains("Decompile"));
            Ok("```c\nint f();\n```".to_owned())
        };
        let plan = plan_at(DisasmQueryType::ConvertToHighLevel, 0);
        let outcome = run_query(&plan, &mut source, Some(&mut ask), 1).expect("outcome");
        let QueryOutcome::ConvertToHighLevel { decompiled, .. } = &outcome else {
            panic!("decompile outcome expected");
        };
        assert_eq!(decompiled.as_deref(), Some("\nint f("));

        let mut source = function_source(2);
        let mut ask = |_: &str, _: &str| Ok("pairs".to_owned());
        let plan = plan_at(DisasmQueryType::FunctionNameAndExplanation, 0);
        let outcome = run_query(&plan, &mut source, Some(&mut ask), 1).expect("outcome");
        assert_eq!(outcome.dialog_title(), "Code explanation");
        assert_eq!(
            outcome.display_prompt(),
            "Give me pairs of name and explanation for this function.sub_401000"
        );
    }

    #[test]
    fn comment_application_plan() {
        let mut source = function_source(0);
        source.lines = vec![
            label("sub_401000"),
            insn("mov", "eax, 0"),
            label("loc_1:"),
            insn("mov", "eax, 1"),
            insn("ret", ""),
        ];
        source.comments.insert(3, "old".to_owned());
        source.ending = 10;
        let comments = vec![
            ("mov eax, 0".to_owned(), "zero".to_owned()),
            ("mov eax, 1".to_owned(), "one".to_owned()),
            ("ret".to_owned(), "leave".to_owned()),
        ];
        let plan = plan_comment_application(&mut source, 0, &comments);
        assert_eq!(
            plan.updates,
            vec![(1, "zero".to_owned()), (3, "one; old".to_owned()), (4, "leave".to_owned())]
        );
        assert!(plan.warnings.is_empty());
        assert!(plan.clear_selection && !plan.aborted);

        // Mismatched first instruction only warns.
        let mismatched = vec![("nop".to_owned(), "x".to_owned())];
        let plan = plan_comment_application(&mut source, 0, &mismatched);
        assert_eq!(plan.warnings, vec![UNEXPECTED_COMMENTS_WARNING]);
        assert_eq!(plan.updates, vec![(1, "x".to_owned())]);

        // Too many comments: abort past the zone end, keeping earlier updates.
        let many: Vec<(String, String)> = (0..6).map(|i| (format!("i{i}"), format!("c{i}"))).collect();
        let plan = plan_comment_application(&mut source, 0, &many);
        assert!(plan.aborted && !plan.clear_selection);
        assert_eq!(plan.updates.len(), 3);

        assert_eq!(
            plan_comment_application(&mut source, 0, &[]).warnings,
            vec![NO_COMMENTS_FOUND_WARNING]
        );
        let mut labels_only = function_source(0);
        labels_only.lines = vec![label("a"), label("b")];
        assert_eq!(
            plan_comment_application(&mut labels_only, 0, &comments).warnings,
            vec![NO_INSTRUCTIONS_FOUND]
        );
    }
}
