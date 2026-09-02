//! `cpp-parity-behavioral-bugs` — assistant-side quirks
//! (`docs/cpp_parity_quirks.md` §1–§3).
//!
//! Each test pins one intentional C++ behaviour that the Rust port
//! replicates on purpose. Changing any of these is a documented
//! deviation, not a bug fix.

use crate::disasm_prompt::{
    build_prompt, AsmLine, DisasmQueryType, ASSEMBLY_HEADER, FUNCTION_NAME_AND_EXPLANATION_INTENDED_PROMPT,
};
use crate::gpt4o::Gpt4oAssistant;
use crate::http::RecordingTransport;
use crate::{AssistantError, SmartAssistantProvider, ERROR_CALLING_GEMINI_API};
use serde_json::{Map, Value};

/// Quirk 1 — `Instance.cpp:1658-1672`: the `FunctionNameAndExplanation`
/// prompt is formatted into a local `LocalString<320>` that is never
/// assigned to `params.prompt`; the model receives an empty prompt
/// followed directly by the assembly header.
#[test]
fn quirk_1_function_name_and_explanation_sends_empty_prompt() {
    let params = DisasmQueryType::FunctionNameAndExplanation.params();
    assert_eq!(params.prompt, "");
    let line = AsmLine {
        size: 1,
        mnemonic: "nop",
        op_str: "",
        comment: None,
    };
    let sent = build_prompt(&params, [line]).expect("prompt");
    assert!(sent.starts_with(ASSEMBLY_HEADER));
    assert!(!sent.contains(FUNCTION_NAME_AND_EXPLANATION_INTENDED_PROMPT));
}

/// Quirk 2 — `CSVFile.cpp:105-106`: `GetSmartAssistantContext` calls
/// `AddUInt("ContentSize", size)` and later `AddUInt("ContentSize",
/// rowsNo)`; the nlohmann object keeps the **last** value, so the
/// "content size" the model sees is the row count. A CSV type plugin
/// must emit the key twice in that order.
#[test]
fn quirk_2_csv_context_duplicate_content_size_key() {
    let file_size: u64 = 4096;
    let rows_no: u64 = 37;
    let columns_no: u64 = 4;
    let mut ctx: Map<String, Value> = Map::new();
    ctx.insert("Name".to_owned(), Value::String("data.csv".to_owned()));
    ctx.insert("ContentSize".to_owned(), Value::from(file_size));
    ctx.insert("ColumnsNumber".to_owned(), Value::from(columns_no));
    let previous = ctx.insert("ContentSize".to_owned(), Value::from(rows_no));
    assert_eq!(previous, Some(Value::from(file_size)), "second AddUInt overwrites");
    assert_eq!(ctx.get("ContentSize"), Some(&Value::from(rows_no)));
    assert_eq!(ctx.len(), 3);
    let sent = crate::tab_context::build_chat_context(Some(&Value::Object(ctx)), "size?", 1024);
    assert_eq!(sent, "{\"ColumnsNumber\":\"4\",\"ContentSize\":\"37\",\"Name\":\"\\\"data.csv\\\"\"}");
}

/// Quirk 3 — `SmartAssistantPlugin.cpp:192-194`: the GPT-4o transport
/// failure path returns the Gemini wording.
#[test]
fn quirk_3_gpt4o_transport_error_reads_gemini() {
    let gpt = Gpt4oAssistant::new(RecordingTransport::failing());
    assert_eq!(gpt.name(), "GPT4o");
    assert_eq!(gpt.ask("p", "d"), Err(AssistantError::new("Error calling Gemini API!")));
    assert_eq!(ERROR_CALLING_GEMINI_API, "Error calling Gemini API!");
}
