# C++ parity quirks (intentional)

The Rust port replicates the behaviour of the C++ `GView` sources, including a
number of behaviours that look like bugs. They are listed here so that nobody
"fixes" them by accident: each one is pinned by a unit test named
`cpp_parity_quirks::*` (run `cargo test cpp_parity_quirks::` from `gview-rs/`).
Deviating from any of them is a documented decision, not a drive-by fix.

Rule of precedence (from `CLAUDE.md`): C++ runtime behaviour wins over the
specs. When a spec and the C++ disagree, the C++ behaviour is implemented and
the discrepancy is noted in `specs/IMPLEMENTATION_TASK_MATRIX.md`.

| # | Quirk | C++ anchor | Rust location | Test |
|---|-------|-----------|---------------|------|
| 1 | `FunctionNameAndExplanation` sends an **empty** prompt | `DissasmViewer/Instance.cpp:1658-1672` | `gview-assistant/src/disasm_prompt.rs` | `gview-assistant` `cpp_parity_quirks::quirk_1_*` |
| 2 | CSV `GetSmartAssistantContext` emits `ContentSize` twice | `Types/CSV/src/CSVFile.cpp:105-106` | (CSV plugin, P1) documented in `gview-assistant/src/cpp_parity_quirks.rs` | `gview-assistant` `cpp_parity_quirks::quirk_2_*` |
| 3 | GPT-4o transport failure says `Error calling Gemini API!` | `Type/SmartAssistantPlugin.cpp:192-194` | `gview-assistant/src/gpt4o.rs` | `gview-assistant` `cpp_parity_quirks::quirk_3_*` |
| 4 | `TextViewer::ShowFindDialog` is a `NOT_IMPLEMENTED` stub | `View/TextViewer/Instance.cpp:1487-1490` | `gview-view/src/text_viewer/input.rs` | `gview-view` `cpp_parity_quirks::quirk_4_*` |
| 5 | Grid `ProcessContent` splits rows at the cache-window boundary (**deliberately fixed** in Rust) | `View/GridViewer/Instance.cpp` `ProcessContent` | `gview-view/src/grid_viewer/parse.rs` | `gview-view` `cpp_parity_quirks::quirk_5_*` |
| 6 | `INSTANCE_CHOOSE_TYPE.CommandId` is `CMD_SWITCH_TO_VIEW` but the handler uses `CMD_CHOSE_NEW_TYPE` | `src/include/Internal.hpp:509`, `App/FileWindow.cpp:289` | `gview-app/src/file_window/events.rs`, `command_bar.rs` | `gview-app` `cpp_parity_quirks::quirk_6_*` |

## 1. `FunctionNameAndExplanation` prompt is never assigned

`Instance::QuerySmartAssistant` formats the intended text ("Suggest 5 pairs of
name and a short statement…") into a `LocalString<320> prompt`, but unlike the
`FunctionName` branch it never does `params.prompt = prompt.GetText()`. The
`QuerySmartAssistantParams::prompt` string view stays empty and the model
receives only `Here is x86 assembly code: \n` plus the listing.

Rust: `DisasmQueryType::FunctionNameAndExplanation.params().prompt == ""`; the
intended text is kept as `FUNCTION_NAME_AND_EXPLANATION_INTENDED_PROMPT` for
reference. (The C++ `AddFormat("%s", nullptr)` on the empty view is undefined
behaviour — common CRTs print `(null)`; that artefact is *not* replicated.)

## 2. CSV context emits `ContentSize` twice

```cpp
builder->AddUInt("ContentSize", obj->GetData().GetSize());
builder->AddUInt("ColumnsNumber", columnsNo);
builder->AddUInt("ContentSize", rowsNo);
```

nlohmann's object keeps the last write, so the "content size" the assistant
sees for a CSV is the **row count**. The CSV type plugin (P1) must emit the
key twice in that order; the tab-context ranking then serialises the row count.

## 3. GPT-4o error message names Gemini

`ChatGPT4oAssistant::AskSmartAssistant` returns the literal
`"Error calling Gemini API!"` when the HTTP call fails (copy-paste from the
Gemini assistant). Both Rust clients return the same text on transport failure.

## 4. `TextViewer` has no find dialog

`Instance::ShowFindDialog()` is `NOT_IMPLEMENTED(false)`. The Rust text viewer
exposes no find action: `text_action_for_key` maps neither Alt+F7 (the
`FindDialog` command key) nor Ctrl+F to anything.

## 5. Grid `ProcessContent` cache-window boundary (deliberate deviation)

The C++ grid parser reads one `DataCache` window per row and silently splits a
row longer than the cache window (`02_VIEWER_GRID` §3.1). The Rust
`process_content` is a chunked state machine that streams the whole object, so
a row spanning the boundary stays one row. This is the one entry in this list
where the port intentionally does **not** replicate the C++ behaviour; the test
pins the fixed behaviour so a future "parity" change is caught.

## 6. `INSTANCE_CHOOSE_TYPE` command id mismatch

`Internal.hpp:509` declares the Alt+F1 `ChooseType` control with
`CommandId = CMD_SWITCH_TO_VIEW`, while `FileWindow.cpp:289` registers the key
with `CMD_CHOSE_NEW_TYPE` and `OnEvent` dispatches on `CMD_CHOSE_NEW_TYPE`. The
Rust `INSTANCE_CHOOSE_TYPE` keeps `CMD_SWITCH_TO_VIEW` as its `command_id`
while `build_command_bar` registers Alt+F1 as `CMD_CHOSE_NEW_TYPE`, exactly as
the C++ does. Only the key-configurator listing shows the mismatched id.

## Related non-truncation notes (not bugs, but spec discrepancies)

- `AppCUI::LocalString<N>` grows on the heap when `AddFormat` overflows; the
  disassembly assistant prompt is therefore **not** capped at 640 bytes
  (`disasm_prompt.rs`, matrix note on `smart-assistant-disasm-prompt`).
- The Gemini request body is `{"contents":{"parts":{"text":…}}}` (nested
  objects, nlohmann brace-elision), not the arrays sketched in spec §2.2.
