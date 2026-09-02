//! Disassembly assistant prompts (`DissasmViewer/Instance.cpp`
//! `QuerySmartAssistant`, `x86_x64/DissasmX86.cpp`
//! `QuerySmartAssistantX86X64`; spec §4.1–4.3, §4.6).
//!
//! Two stages, both pure:
//!
//! 1. [`DisasmQueryType::params`] — the verbatim per-query
//!    `QuerySmartAssistantParams` (display prompt, model prompt,
//!    `sub_` gate, flags);
//! 2. [`build_prompt`] — `QuerySmartAssistantX86X64`'s line walk and
//!    buffer assembly over an iterator of [`AsmLine`]s supplied by the
//!    viewer (the zone walk itself stays with the viewer).
//!
//! C++ parity notes:
//! - `FunctionNameAndExplanation` builds its prompt into a local
//!   `LocalString<320>` but never assigns `params.prompt`
//!   (`Instance.cpp:1658-1672`), so the model receives an **empty**
//!   prompt. Replicated: [`QueryParams::prompt`] is `""` for that
//!   query; the intended text is kept in
//!   [`FUNCTION_NAME_AND_EXPLANATION_INTENDED_PROMPT`] for reference.
//!   (The C++ `AddFormat("%s", nullptr)` on that empty `string_view`
//!   is undefined behaviour; common CRTs print `(null)`. Not
//!   replicated.)
//! - `DISSASM_ASSISTANT_MAX_BYTE_TO_SEND` (640) sizes the
//!   `LocalString<640>` stack buffer, but `AppCUI::String::AddFormat`
//!   heap-grows on overflow (`String::Grow`), so **the C++ prompt is
//!   never truncated**. Spec §4.2 / §9 describe a cap; C++ wins — the
//!   builder never truncates, and [`MAX_BYTE_TO_SEND`] is exposed only
//!   as the documented constant. Same for the `LocalString<64>` line
//!   scratch and the `LocalString<128>` display prompt.
//! - the end-of-function test `*(uint32*) mnemonic == retOP` compares
//!   the first four bytes with `"ret\0"`, i.e. the mnemonic is exactly
//!   `ret` (`retn`, `retf` do not stop the walk);
//! - `mnemonicStarsWith` is checked with `memcmp` over the prefix
//!   length → `starts_with`.

/// `DISSASM_ASSISTANT_MAX_DISSASM_LINES_SENT`.
pub const MAX_DISSASM_LINES_SENT: u32 = 100;
/// `DISSASM_ASSISTANT_MAX_DISSASM_LINES_ANALYSED`.
pub const MAX_DISSASM_LINES_ANALYSED: u32 = 150;
/// `DISSASM_ASSISTANT_MAX_API_CALLS`.
pub const MAX_API_CALLS: u32 = 10;
/// `DISSASM_ASSISTANT_MAX_BYTE_TO_SEND` — initial stack capacity of
/// the C++ prompt buffer; **not** a truncation limit (see module docs).
pub const MAX_BYTE_TO_SEND: usize = 640;
/// `DISSASM_ASSISTANT_FUNCTION_NAMES_TO_REQUEST`.
pub const FUNCTION_NAMES_TO_REQUEST: u32 = 5;

/// Prefix required by the function-start gate.
pub const FUNCTION_START_PREFIX: &str = "sub_";
/// `mnemonicStartsWithError` (`FunctionName`, `FunctionNameAndExplanation`).
pub const NOT_FUNCTION_START_ERROR: &str =
    "This is not a function start! Please select a \"sub\" instruction! If they are not available please enable DeepScanning.";

/// `FunctionName` `displayPrompt` (trailing space, mnemonic appended).
pub const FUNCTION_NAME_DISPLAY_PROMPT: &str = "Give me an appropriate name for the function: ";
/// `FunctionName` `prompt` (`%u` = [`FUNCTION_NAMES_TO_REQUEST`]).
pub const FUNCTION_NAME_PROMPT: &str = "Suggest 5 names for this code based on what it does separated by comma. Write only the names, separated by comma, do not write anything else. Do not write any symbols, just the names. ";
/// `ExplainCode` `displayPrompt`.
pub const EXPLAIN_CODE_DISPLAY_PROMPT: &str = "Explain the selected code";
/// `ExplainCode` `prompt` (typos verbatim).
pub const EXPLAIN_CODE_PROMPT: &str = "Explain what this x86/x84 assembly code does. Please also add a new section at the end for comments where you explain each line in order and suggest maximum 8 words for comments describing what happens in than line. Please mark the new section by writing CommentsZoneExplained and then on the new line they start.The format for the this section should be instruction found separated by # character and then the comment without additional special characters.";
/// `ConvertToHighLevel` `displayPrompt`.
pub const CONVERT_TO_HIGH_LEVEL_DISPLAY_PROMPT: &str = "Decompile the following assembly into a higher level language.";
/// `ConvertToHighLevel` `prompt`.
pub const CONVERT_TO_HIGH_LEVEL_PROMPT: &str =
    "Decompile the following assembly into a higher level language in C. Surround the code with \"```\"";
/// `FunctionNameAndExplanation` `displayPrompt`.
pub const FUNCTION_NAME_AND_EXPLANATION_DISPLAY_PROMPT: &str = "Give me pairs of name and explanation for this function.";
/// The text `Instance.cpp:1659-1664` formats but never assigns.
pub const FUNCTION_NAME_AND_EXPLANATION_INTENDED_PROMPT: &str = "Suggest 5 pairs of name and a short statement. The name must be first and on the next line a statement. Each pair must be separated by 2 new lines.Write only the text, do not write anything else. Do not write any symbols, just the pairs. ";
/// `MitreTechniques` `displayPrompt`.
pub const MITRE_TECHNIQUES_DISPLAY_PROMPT: &str = "What are the MITRE techniques associated with the following assembly code?";
/// `MitreTechniques` `prompt`.
pub const MITRE_TECHNIQUES_PROMPT: &str = "What is the MITRE techniques associated with the following assembly code (if any)? Only provide MITRE techniques where they can be inferred from the assembly code. Do not consider a MITRE technique if the file can potentially be part of an attack chain where you need further context to evaluate. If any technique is found, use the MITRE format: T<techniqueID>.<sub-techniqueID>.";

/// Header emitted after the prompt (`"Here is x86 assembly code: \n"`).
pub const ASSEMBLY_HEADER: &str = "Here is x86 assembly code: \n";
/// Header for the overflow `call` lines.
pub const API_CALLS_HEADER: &str = "The function also makes these API calls: ";
/// Indentation of every instruction line (`"   %s %s"`).
pub const LINE_INDENT: &str = "   ";
/// Comment separator (`" ; %s"`).
pub const COMMENT_SEPARATOR: &str = " ; ";
/// `"No instructions found!"` warning.
pub const NO_INSTRUCTIONS_FOUND: &str = "No instructions found!";
/// `"Please make a single selection on a dissasm zone to select some code!"`.
pub const SELECTION_REQUIRED_WARNING: &str = "Please make a single selection on a dissasm zone to select some code!";

/// Mnemonic that ends the walk when `stop_at_end_of_function` is set
/// (`retOP` = bytes `"ret\0"`).
pub const RET_MNEMONIC: &str = "ret";
/// Instructions collected as API calls once the send cap is reached.
pub const CALL_PREFIX: &str = "call";

/// `QueryTypeSmartAssistant` (spec §8 `DisasmQueryType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DisasmQueryType {
    /// Ctrl+K / menu 11.
    FunctionName,
    /// Menu 12 (selection required).
    ExplainCode,
    /// Menu 13 (selection required).
    ConvertToHighLevel,
    /// Menu 14.
    FunctionNameAndExplanation,
    /// Ctrl+L / menu 15 (C++ spelling `MitreTechiques`).
    MitreTechniques,
}

/// C++ `QuerySmartAssistantParams`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryParams {
    /// Stop the walk after the first `ret`.
    pub stop_at_end_of_function: bool,
    /// Append the cursor line's mnemonic to the display prompt.
    pub display_prompt_uses_mnemonic: bool,
    /// Append ` ; <comment>` to lines that carry a user comment.
    pub include_comments: bool,
    /// Required mnemonic prefix of the cursor line (`""` = no gate).
    pub mnemonic_starts_with: &'static str,
    /// Warning shown when the gate fails.
    pub mnemonic_starts_with_error: &'static str,
    /// Text shown in the UI for the query.
    pub display_prompt: &'static str,
    /// Text sent to the model ahead of the assembly listing.
    pub prompt: &'static str,
}

impl DisasmQueryType {
    /// All five query kinds in `QueryTypeSmartAssistant` order.
    pub const ALL: [Self; 5] = [
        Self::FunctionName,
        Self::ExplainCode,
        Self::ConvertToHighLevel,
        Self::FunctionNameAndExplanation,
        Self::MitreTechniques,
    ];

    /// `Instance.cpp:1589-1590`: which kinds need an active selection
    /// (the others work from the cursor line; spec §3.4).
    #[must_use]
    pub const fn requires_selection(self) -> bool {
        matches!(self, Self::ExplainCode | Self::ConvertToHighLevel)
    }

    /// `QuerySmartAssistantParams` for this kind (`Instance.cpp:1625-1679`).
    #[must_use]
    pub const fn params(self) -> QueryParams {
        match self {
            Self::FunctionName => QueryParams {
                stop_at_end_of_function: true,
                display_prompt_uses_mnemonic: true,
                include_comments: false,
                mnemonic_starts_with: FUNCTION_START_PREFIX,
                mnemonic_starts_with_error: NOT_FUNCTION_START_ERROR,
                display_prompt: FUNCTION_NAME_DISPLAY_PROMPT,
                prompt: FUNCTION_NAME_PROMPT,
            },
            Self::ExplainCode => QueryParams {
                stop_at_end_of_function: false,
                display_prompt_uses_mnemonic: false,
                include_comments: false,
                mnemonic_starts_with: "",
                mnemonic_starts_with_error: "",
                display_prompt: EXPLAIN_CODE_DISPLAY_PROMPT,
                prompt: EXPLAIN_CODE_PROMPT,
            },
            Self::ConvertToHighLevel => QueryParams {
                stop_at_end_of_function: false,
                display_prompt_uses_mnemonic: true,
                include_comments: true,
                mnemonic_starts_with: "",
                mnemonic_starts_with_error: "",
                display_prompt: CONVERT_TO_HIGH_LEVEL_DISPLAY_PROMPT,
                prompt: CONVERT_TO_HIGH_LEVEL_PROMPT,
            },
            Self::FunctionNameAndExplanation => QueryParams {
                stop_at_end_of_function: true,
                display_prompt_uses_mnemonic: true,
                include_comments: false,
                mnemonic_starts_with: FUNCTION_START_PREFIX,
                mnemonic_starts_with_error: NOT_FUNCTION_START_ERROR,
                display_prompt: FUNCTION_NAME_AND_EXPLANATION_DISPLAY_PROMPT,
                // C++ never assigns `params.prompt` here (parity bug).
                prompt: "",
            },
            Self::MitreTechniques => QueryParams {
                stop_at_end_of_function: true,
                display_prompt_uses_mnemonic: true,
                include_comments: true,
                mnemonic_starts_with: "",
                mnemonic_starts_with_error: "",
                display_prompt: MITRE_TECHNIQUES_DISPLAY_PROMPT,
                prompt: MITRE_TECHNIQUES_PROMPT,
            },
        }
    }
}

/// Spec §8 `DisasmAssistantContext` — the four walk limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisasmAssistantContext {
    /// Lines copied into the listing.
    pub max_lines_sent: u32,
    /// Lines inspected (the surplus only feeds the API-call list).
    pub max_lines_analysed: u32,
    /// Overflow `call` lines kept.
    pub max_api_calls: u32,
    /// Initial prompt buffer size.
    pub max_bytes: usize,
}

impl Default for DisasmAssistantContext {
    fn default() -> Self {
        Self {
            max_lines_sent: MAX_DISSASM_LINES_SENT,
            max_lines_analysed: MAX_DISSASM_LINES_ANALYSED,
            max_api_calls: MAX_API_CALLS,
            max_bytes: MAX_BYTE_TO_SEND,
        }
    }
}

/// One zone line as returned by `GetCurrentAsmLine` plus its comment
/// (`GetComment`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsmLine<'a> {
    /// Instruction byte length; `0` marks a non-instruction line
    /// (label / structure text) whose `mnemonic` is copied as-is.
    pub size: u32,
    /// Mnemonic (or the whole text for `size == 0` lines).
    pub mnemonic: &'a str,
    /// Operand string.
    pub op_str: &'a str,
    /// User comment attached to the line, if any.
    pub comment: Option<&'a str>,
}

/// Failures of [`display_prompt`] / [`build_prompt`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptError {
    /// The cursor line does not start with
    /// [`QueryParams::mnemonic_starts_with`]; carries the warning text.
    NotFunctionStart(&'static str),
    /// The walk produced no listing line (`"No instructions found!"`).
    NoInstructions,
}

impl core::fmt::Display for PromptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFunctionStart(text) => f.write_str(text),
            Self::NoInstructions => f.write_str(NO_INSTRUCTIONS_FOUND),
        }
    }
}

impl std::error::Error for PromptError {}

/// `DissasmX86.cpp:2030-2038`: the display prompt for a query.
///
/// The cursor mnemonic is appended when the query asks for it, after
/// the `sub_` gate. `cursor_mnemonic` is the mnemonic of the line the
/// query was invoked on (spec §3.3).
///
/// # Errors
///
/// [`PromptError::NotFunctionStart`] when the gate is set and fails.
pub fn display_prompt(params: &QueryParams, cursor_mnemonic: &str) -> Result<String, PromptError> {
    let mut text = String::from(params.display_prompt);
    if !params.mnemonic_starts_with.is_empty() {
        if !cursor_mnemonic.starts_with(params.mnemonic_starts_with) {
            return Err(PromptError::NotFunctionStart(params.mnemonic_starts_with_error));
        }
        if params.display_prompt_uses_mnemonic {
            text.push_str(cursor_mnemonic);
        }
    }
    Ok(text)
}

/// Lines gathered by the walk (`assemblyLines`, `apisInstructions`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CollectedLines {
    /// Up to [`MAX_DISSASM_LINES_SENT`] listing lines.
    pub assembly: Vec<String>,
    /// Up to [`MAX_API_CALLS`] `call` lines seen after the listing
    /// filled up.
    pub api_calls: Vec<String>,
    /// Whether the walk ended on a `ret` (informational).
    pub stopped_at_ret: bool,
}

/// `DissasmX86.cpp:2052-2082`: walks the lines **after** the cursor
/// line, in order, applying the analysed / sent / API-call caps and
/// the `ret` stop.
pub fn collect_lines<'a>(params: &QueryParams, lines: impl IntoIterator<Item = AsmLine<'a>>) -> CollectedLines {
    let mut out = CollectedLines::default();
    let sent_cap = MAX_DISSASM_LINES_SENT as usize;
    let api_cap = MAX_API_CALLS as usize;
    for line in lines.into_iter().take(MAX_DISSASM_LINES_ANALYSED as usize) {
        if line.size > 0 {
            let mut current = format!("{LINE_INDENT}{} {}", line.mnemonic, line.op_str);
            if out.assembly.len() < sent_cap {
                if params.include_comments {
                    if let Some(comment) = line.comment {
                        current.push_str(COMMENT_SEPARATOR);
                        current.push_str(comment);
                    }
                }
                out.assembly.push(current);
            } else if line.mnemonic.starts_with(CALL_PREFIX) && out.api_calls.len() < api_cap {
                out.api_calls.push(current);
            }
        } else if out.assembly.len() < sent_cap {
            out.assembly.push(line.mnemonic.to_owned());
        }
        if params.stop_at_end_of_function && line.mnemonic == RET_MNEMONIC {
            out.stopped_at_ret = true;
            break;
        }
    }
    out
}

/// `DissasmX86.cpp:2088-2100`: the final prompt text.
///
/// # Errors
///
/// [`PromptError::NoInstructions`] when no listing line was collected.
pub fn assemble_prompt(params: &QueryParams, collected: &CollectedLines) -> Result<String, PromptError> {
    if collected.assembly.is_empty() {
        return Err(PromptError::NoInstructions);
    }
    let mut buffer = String::with_capacity(MAX_BYTE_TO_SEND);
    buffer.push_str(params.prompt);
    buffer.push_str(ASSEMBLY_HEADER);
    for line in &collected.assembly {
        buffer.push_str(line);
        buffer.push('\n');
    }
    if !collected.api_calls.is_empty() {
        buffer.push_str(API_CALLS_HEADER);
        for call in &collected.api_calls {
            buffer.push_str(call);
            buffer.push('\n');
        }
    }
    Ok(buffer)
}

/// [`collect_lines`] + [`assemble_prompt`].
///
/// # Errors
///
/// [`PromptError::NoInstructions`] when the walk yields nothing.
pub fn build_prompt<'a>(params: &QueryParams, lines: impl IntoIterator<Item = AsmLine<'a>>) -> Result<String, PromptError> {
    assemble_prompt(params, &collect_lines(params, lines))
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn insn<'a>(mnemonic: &'a str, op_str: &'a str) -> AsmLine<'a> {
        AsmLine {
            size: 1,
            mnemonic,
            op_str,
            comment: None,
        }
    }

    #[test]
    fn all_five_prompts_verbatim() {
        let p = DisasmQueryType::FunctionName.params();
        assert_eq!(p.display_prompt, "Give me an appropriate name for the function: ");
        assert_eq!(p.prompt, "Suggest 5 names for this code based on what it does separated by comma. Write only the names, separated by comma, do not write anything else. Do not write any symbols, just the names. ");
        assert_eq!(p.mnemonic_starts_with, "sub_");
        assert_eq!(p.mnemonic_starts_with_error, "This is not a function start! Please select a \"sub\" instruction! If they are not available please enable DeepScanning.");
        assert!(p.stop_at_end_of_function && p.display_prompt_uses_mnemonic && !p.include_comments);

        let p = DisasmQueryType::ExplainCode.params();
        assert_eq!(p.display_prompt, "Explain the selected code");
        assert_eq!(p.prompt, "Explain what this x86/x84 assembly code does. Please also add a new section at the end for comments where you explain each line in order and suggest maximum 8 words for comments describing what happens in than line. Please mark the new section by writing CommentsZoneExplained and then on the new line they start.The format for the this section should be instruction found separated by # character and then the comment without additional special characters.");
        assert!(!p.stop_at_end_of_function && !p.display_prompt_uses_mnemonic && !p.include_comments);
        assert!(p.mnemonic_starts_with.is_empty());

        let p = DisasmQueryType::ConvertToHighLevel.params();
        assert_eq!(p.display_prompt, "Decompile the following assembly into a higher level language.");
        assert_eq!(p.prompt, "Decompile the following assembly into a higher level language in C. Surround the code with \"```\"");
        assert!(!p.stop_at_end_of_function && p.display_prompt_uses_mnemonic && p.include_comments);

        let p = DisasmQueryType::FunctionNameAndExplanation.params();
        assert_eq!(p.display_prompt, "Give me pairs of name and explanation for this function.");
        assert_eq!(p.prompt, "", "C++ never assigns params.prompt (Instance.cpp:1658-1672)");
        assert_eq!(FUNCTION_NAME_AND_EXPLANATION_INTENDED_PROMPT, "Suggest 5 pairs of name and a short statement. The name must be first and on the next line a statement. Each pair must be separated by 2 new lines.Write only the text, do not write anything else. Do not write any symbols, just the pairs. ");
        assert_eq!(p.mnemonic_starts_with, "sub_");
        assert!(p.stop_at_end_of_function && p.display_prompt_uses_mnemonic && !p.include_comments);

        let p = DisasmQueryType::MitreTechniques.params();
        assert_eq!(p.display_prompt, "What are the MITRE techniques associated with the following assembly code?");
        assert_eq!(p.prompt, "What is the MITRE techniques associated with the following assembly code (if any)? Only provide MITRE techniques where they can be inferred from the assembly code. Do not consider a MITRE technique if the file can potentially be part of an attack chain where you need further context to evaluate. If any technique is found, use the MITRE format: T<techniqueID>.<sub-techniqueID>.");
        assert!(p.stop_at_end_of_function && p.display_prompt_uses_mnemonic && p.include_comments);
        assert!(p.mnemonic_starts_with.is_empty());
    }

    #[test]
    fn selection_rules_and_constants() {
        assert!(DisasmQueryType::ExplainCode.requires_selection());
        assert!(DisasmQueryType::ConvertToHighLevel.requires_selection());
        assert!(!DisasmQueryType::FunctionName.requires_selection());
        assert!(!DisasmQueryType::MitreTechniques.requires_selection());
        assert!(!DisasmQueryType::FunctionNameAndExplanation.requires_selection());
        assert_eq!(DisasmQueryType::ALL.len(), 5);
        let ctx = DisasmAssistantContext::default();
        assert_eq!((ctx.max_lines_sent, ctx.max_lines_analysed, ctx.max_api_calls, ctx.max_bytes), (100, 150, 10, 640));
        assert_eq!(FUNCTION_NAMES_TO_REQUEST, 5);
    }

    #[test]
    fn display_prompt_gate_and_mnemonic_suffix() {
        let fname = DisasmQueryType::FunctionName.params();
        assert_eq!(
            display_prompt(&fname, "sub_401000"),
            Ok("Give me an appropriate name for the function: sub_401000".to_owned())
        );
        assert_eq!(
            display_prompt(&fname, "mov"),
            Err(PromptError::NotFunctionStart(NOT_FUNCTION_START_ERROR))
        );
        assert_eq!(display_prompt(&fname, "sub"), Err(PromptError::NotFunctionStart(NOT_FUNCTION_START_ERROR)));
        assert_eq!(
            PromptError::NotFunctionStart(NOT_FUNCTION_START_ERROR).to_string(),
            NOT_FUNCTION_START_ERROR
        );
        // No gate → mnemonic is NOT appended even when the flag is set
        // (the append lives inside the gate branch in C++).
        let mitre = DisasmQueryType::MitreTechniques.params();
        assert_eq!(display_prompt(&mitre, "mov"), Ok(MITRE_TECHNIQUES_DISPLAY_PROMPT.to_owned()));
        let explain = DisasmQueryType::ExplainCode.params();
        assert_eq!(display_prompt(&explain, "anything"), Ok(EXPLAIN_CODE_DISPLAY_PROMPT.to_owned()));
    }

    #[test]
    fn prompt_assembly_basic_layout() {
        let params = DisasmQueryType::FunctionName.params();
        let lines = [insn("push", "ebp"), insn("mov", "ebp, esp"), insn("ret", ""), insn("nop", "")];
        let prompt = build_prompt(&params, lines).expect("prompt");
        assert_eq!(
            prompt,
            format!("{FUNCTION_NAME_PROMPT}Here is x86 assembly code: \n   push ebp\n   mov ebp, esp\n   ret \n")
        );
        let collected = collect_lines(&params, lines);
        assert!(collected.stopped_at_ret);
        assert_eq!(collected.assembly.len(), 3);
    }

    #[test]
    fn ret_stop_only_when_requested_and_only_exact_ret() {
        let explain = DisasmQueryType::ExplainCode.params();
        let lines = [insn("ret", ""), insn("nop", "")];
        assert_eq!(collect_lines(&explain, lines).assembly.len(), 2);
        let fname = DisasmQueryType::FunctionName.params();
        let lines = [insn("retn", ""), insn("retf", ""), insn("nop", "")];
        let c = collect_lines(&fname, lines);
        assert_eq!(c.assembly.len(), 3);
        assert!(!c.stopped_at_ret);
    }

    #[test]
    fn comments_only_with_include_comments() {
        let commented = AsmLine {
            size: 2,
            mnemonic: "call",
            op_str: "0x401000",
            comment: Some("init"),
        };
        let mitre = DisasmQueryType::MitreTechniques.params();
        assert_eq!(collect_lines(&mitre, [commented]).assembly, vec!["   call 0x401000 ; init".to_owned()]);
        let fname = DisasmQueryType::FunctionName.params();
        assert_eq!(collect_lines(&fname, [commented]).assembly, vec!["   call 0x401000".to_owned()]);
    }

    #[test]
    fn size_zero_lines_are_copied_verbatim() {
        let label = AsmLine {
            size: 0,
            mnemonic: "sub_401000:",
            op_str: "",
            comment: None,
        };
        let c = collect_lines(&DisasmQueryType::ExplainCode.params(), [label, insn("nop", "")]);
        assert_eq!(c.assembly, vec!["sub_401000:".to_owned(), "   nop ".to_owned()]);
    }

    #[test]
    fn line_caps_100_sent_150_analysed_10_api_calls() {
        let params = DisasmQueryType::ExplainCode.params();
        // 200 lines: the first 100 are sent; among 101..150 every line
        // is a `call` → only 10 kept; 151..200 never looked at.
        let lines = (0..200u32).map(|i| if i >= 100 { insn("call", "api") } else { insn("nop", "") });
        let c = collect_lines(&params, lines);
        assert_eq!(c.assembly.len(), 100);
        assert_eq!(c.api_calls.len(), 10);
        assert!(c.api_calls.iter().all(|l| l == "   call api"));

        // Non-call overflow lines are dropped; a `callq`-style mnemonic
        // still counts (`memcmp` prefix check).
        let lines = (0..120u32).map(|i| if i >= 100 && i % 2 == 0 { insn("callq", "x") } else { insn("nop", "") });
        let c = collect_lines(&params, lines);
        assert_eq!(c.api_calls.len(), 10);

        // Analysed cap: calls past line 150 are never seen.
        let lines = (0..300u32).map(|i| if i >= 160 { insn("call", "late") } else { insn("nop", "") });
        assert!(collect_lines(&params, lines).api_calls.is_empty());

        // Size-0 lines past the send cap are ignored.
        let lines = (0..110u32).map(|i| {
            if i >= 100 {
                AsmLine {
                    size: 0,
                    mnemonic: "label:",
                    op_str: "",
                    comment: None,
                }
            } else {
                insn("nop", "")
            }
        });
        assert_eq!(collect_lines(&params, lines).assembly.len(), 100);
    }

    #[test]
    fn api_calls_section_layout() {
        let params = DisasmQueryType::MitreTechniques.params();
        let lines = (0..102u32).map(|i| if i >= 100 { insn("call", "CreateFileW") } else { insn("nop", "") });
        let prompt = build_prompt(&params, lines).expect("prompt");
        assert!(prompt.starts_with(MITRE_TECHNIQUES_PROMPT));
        assert!(prompt.ends_with("The function also makes these API calls:    call CreateFileW\n   call CreateFileW\n"));
        assert_eq!(prompt.matches("   nop \n").count(), 100);
    }

    #[test]
    fn prompt_assembly_640_cap() {
        // Spec §9 calls this the "640-byte cap"; the C++ buffer is a
        // `LocalString<640>` that heap-grows, so parity means: no
        // truncation, everything the walk collected is sent.
        let params = DisasmQueryType::ExplainCode.params();
        let long_line = insn("mov", "qword ptr [rsp + 0x1234567890], 0x1122334455667788");
        let lines = core::iter::repeat_n(long_line, 100);
        let prompt = build_prompt(&params, lines).expect("prompt");
        assert!(prompt.len() > MAX_BYTE_TO_SEND);
        assert_eq!(prompt.matches("   mov qword ptr [rsp + 0x1234567890], 0x1122334455667788\n").count(), 100);
        assert!(prompt.ends_with('\n'));
        assert_eq!(MAX_BYTE_TO_SEND, 640);
    }

    #[test]
    fn empty_walk_is_no_instructions() {
        let params = DisasmQueryType::FunctionName.params();
        assert_eq!(build_prompt(&params, []), Err(PromptError::NoInstructions));
        assert_eq!(PromptError::NoInstructions.to_string(), "No instructions found!");
    }

    #[test]
    fn function_name_and_explanation_sends_empty_prompt() {
        let params = DisasmQueryType::FunctionNameAndExplanation.params();
        let prompt = build_prompt(&params, [insn("nop", "")]).expect("prompt");
        assert!(prompt.starts_with(ASSEMBLY_HEADER));
    }
}
