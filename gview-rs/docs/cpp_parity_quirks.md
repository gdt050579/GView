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
| 7 | The `updateConfig` command is unreachable: the table entry is lowercase and `main` has no `case` for it (**deliberately fixed** in Rust) | `GView/src/GView.cpp` `commands[]`, `main` switch | `gview-app/src/cli.rs` | `gview-app` `cpp_parity_quirks::quirk_7_*` |
| 8 | The cache size is written as `CacheSize` but read as `Config.CacheSize`; `Key.AnalysisEngine` is read but never written | `App/GViewApp.cpp` `ResetConfiguration` L109, `App/Instance.cpp` `LoadSettings` L117, `Internal.hpp:514` | `gview-app/src/settings.rs` | `gview-app` `cpp_parity_quirks::quirk_8_*` |

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

## 7. `updateConfig` is unreachable in C++ (deliberate deviation)

Two independent defects make the documented `updateConfig` command impossible to
invoke:

1. `commands[]` registers the name as `"updateconfig"` and `GetCommandID`
   compares string views directly, so the spelling printed in the help text
   (`GView updateConfig`) never matches. It falls through to `CommandID::Unknown`
   and is opened as a **file name**.
2. Even the exact lowercase `updateconfig` maps to `CommandID::UpdateConfig`,
   which has **no `case`** in the `main` switch. It reaches `default:` and prints
   `Unable to process command: updateconfig` before returning 1.

`cli::parse` reports `CliCommand::UpdateConfig` for the lowercase spelling
(faithful to `commands[]`) and treats `updateConfig` as a path (faithful to the
case-sensitive comparison). Unlike C++, the Rust `main` **dispatches** the
command to the settings updater; the help text advertises it, and leaving a
documented command dead serves nobody. This is the second entry, after quirk 5,
where the port intentionally does not replicate the C++ behaviour.

## 8. Settings written under one key and read under another

`ResetConfiguration` writes the default cache size as

```ini
[GView]
CacheSize = 10485760
```

but `LoadSettings` reads `sect.GetValue("Config.CacheSize")`. A freshly
generated file therefore never supplies the value it was meant to seed, and the
cache size silently falls back to `DEFAULT_CACHE_SIZE` until a user adds the
`Config.CacheSize` key by hand.

The same asymmetry affects the key bindings. `ResetConfiguration` writes the six
entries of its local `localKeys` array, while `LoadSettings` walks the seven
entries of `GViewCommands` (`Internal.hpp:514`), which also contains
`INSTANCE_ANALYSIS_ENGINE`. `Key.AnalysisEngine` is therefore read from every
file and written to none.

Rust keeps both halves visible: `render_gview_section` writes exactly the six
`WRITTEN_KEY_COMMANDS` under `CacheSize`, and the loader walks the seven
`READ_KEY_COMMANDS`. `read_cache_size` accepts **either** key, preferring the
documented read key `Config.CacheSize`, so a generated file behaves the way the
C++ author intended without breaking a hand-written one.

## 9. `UpdateViewSizes` never re-fits the column count to the width

`00_APP` (matrix task `buffer-view-control`) says a `BufferView` resized to 40
columns "switches to 8 data columns per `update_view_sizes`". The C++ anchor
does not do that.

`Instance::OnAfterResize` (`BufferViewer/Instance.cpp:1057-1060`) calls
`UpdateViewSizes` and nothing else, and `UpdateViewSizes`
(`Instance.cpp:617-653`) recomputes only the derived geometry — `xName`,
`xAddress`, `xNumbers`, `xText`, `charactersPerLine` and `visibleRows`. It reads
`Layout.nrCols` but never writes it. The only writer is
`BUFFERVIEW_CMD_CHANGECOL` (F6), which cycles `0 → 8 → 16 → 32 → 0`.

A narrow terminal therefore keeps its 16 columns in the C++ and simply clips the
right-hand bands, and `charactersPerLine` stays at `nrCols`. Rust reproduces
that: `BufferView::on_resize` calls `BufferLayout::update_view_sizes` and
re-clamps the cursor, and only `NavAction::ChangeColumnsCount` moves `nr_cols`
through `next_columns_count`. **C++ wins over the matrix wording**
(`CLAUDE.md §3`, anchor-first).

## 10. `ContainerView` cannot be an `AppCUI-rs` `TreeView<TreeNode>`

`00_APP §5.3.2` sketches the container page as an `AppCUI` `TreeView<TreeNode>`
plus a `ListView` of the plugin's properties, mirroring the C++ constructor
(`ContainerViewer/Instance.cpp:40-76`).

That does not translate. The C++ builds its columns at runtime —

```cpp
for (uint32 idx = 0; idx < settings->columnsCount; idx++)
    this->items->AddColumn(settings->columns[idx].layout);
```

— from the layout strings a plugin ships in `ContainerViewerRequest::columns`
(`"n:&Filename,a:l,w:80"`, …). `AppCUI-rs` `TreeView<T>` instead reads its
columns from `ListItem::columns_count()` / `ListItem::column(i)`, which are
**associated** functions: the column set is fixed per Rust type at compile time,
and there is no `TreeView::add_column`. A plugin's runtime column list cannot
reach it.

`CLAUDE.md §3` puts `AppCUI-rs/` source above the guide and the spec on UI API
questions, so `ContainerView` is a `#[CustomControl]` that owns the
`ContainerTree` and paints the tree, the column header and the property block
itself. This keeps the plugin's runtime columns, keeps one copy of the tree
(the C++ duplicates state between `TreeView` items and the enumerator), and
matches the pattern the other six viewers already use. Lazy population,
idempotence and the leaf-only open rule are unchanged — they live in
`ContainerTree::populate_item` / `on_tree_view_item_pressed`.

## 11. `Close All except current` closes every window

**C++:** `GViewCore/src/App/Instance.cpp:63-73` — `menuWindowList`.

```cpp
{ "Close", MenuCommands::CLOSE, Key::None },
{ "Close &All", MenuCommands::CLOSE_ALL, Key::None },
{ "Close All e&xcept current", MenuCommands::CLOSE_ALL, Key::None },
```

The third entry is bound to `MenuCommands::CLOSE_ALL`, not to
`MenuCommands::CLOSE_ALL_EXCEPT_CURRENT` (which the enum does define,
`Internal.hpp:462-487`). Picking it therefore closes **every** window,
including the current one, and `CLOSE_ALL_EXCEPT_CURRENT` is never
dispatched by any menu item. `Instance::OnEvent` handles neither id, so
in the C++ both entries are in fact inert.

**Port:** `gview-app/src/desktop.rs` `build_menus` binds the same
`Commands::CloseAll` to both entries, so the observable behaviour
matches. `Commands::CloseAllExceptCurrent` still exists and still maps
to `MenuCommands::CLOSE_ALL_EXCEPT_CURRENT` in `menu_id_for_command`,
so the id is preserved for a future fix; `run_desktop_command` routes it
to `close_all` as well.

Unlike the C++, the port *implements* `Close` and `Close All` (the C++
`OnEvent` switch has no case for either, so the entries do nothing at
all). That is a deliberate deviation: an unimplemented menu entry is
indistinguishable from a hang, and `00_APP §5.1.4` specifies both
actions.

Numbering note: `00_APP §5.1.2` calls this "quirk #8" and the matrix
task calls it "#9"; both numbers were already taken by
`settings-bootstrap` and `grid-view-control`, so it is recorded here as
#11.

## Related non-truncation notes (not bugs, but spec discrepancies)

- `AppCUI::LocalString<N>` grows on the heap when `AddFormat` overflows; the
  disassembly assistant prompt is therefore **not** capped at 640 bytes
  (`disasm_prompt.rs`, matrix note on `smart-assistant-disasm-prompt`).
- The Gemini request body is `{"contents":{"parts":{"text":…}}}` (nested
  objects, nlohmann brace-elision), not the arrays sketched in spec §2.2.
