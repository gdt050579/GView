//! Disassembly assistant response parsers (`DissasmX86.cpp`
//! `QuerySmartAssistantX86X64` result handling, `findMostCommonNames`,
//! `QueryShowCodeDialog`, `QueryFunctionNameDialog`; spec §4.4, §4.6).
//!
//! | Query | Parser |
//! |-------|--------|
//! | `FunctionName` | [`parse_function_names`] per retry, [`find_most_common_names`] when `PromptRetries != 1` — see [`FunctionNameOutcome`] |
//! | `ExplainCode` | [`parse_comments_zone`] (`CommentsZoneExplained`, split on the last `#`) |
//! | `ConvertToHighLevel` | [`extract_decompiled_code`] (between the first two ` ``` `) |
//! | `MitreTechiques` | display only ([`MITRE_TECHNIQUES_TITLE`]) |
//! | `FunctionNameAndExplanation` | display only with `needComments` ([`CODE_EXPLANATION_TITLE`]) |
//!
//! C++ quirks reproduced:
//! - `std::getline(ss, name, ',')` keeps empty tokens, so `"a,,b"`
//!   yields three names including an empty one;
//! - after the retry loop the rename uses `names[index]` — the names
//!   of the **last** response — while the dialog listed the merged /
//!   most-common `namesToShow` ([`FunctionNameOutcome::rename_target`]);
//! - the decompile extraction keeps `codeEnd - codeStart - 3` bytes,
//!   i.e. it drops the last three characters before the closing
//!   fence (`DissasmX86.cpp:1920-1941`).

use std::collections::HashMap;

/// `QueryShowCodeDialog` title for `ExplainCode` / `ConvertToHighLevel` /
/// `FunctionNameAndExplanation`.
pub const CODE_EXPLANATION_TITLE: &str = "Code explanation";
/// `QueryShowCodeDialog` title for `MitreTechniques`.
pub const MITRE_TECHNIQUES_TITLE: &str = "MITRE techniques";
/// `QueryFunctionNameDialog` title.
pub const NAME_SELECTOR_TITLE: &str = "Name selector";
/// Marker line that starts the comment section of an `ExplainCode`
/// answer.
pub const COMMENTS_ZONE_MARKER: &str = "CommentsZoneExplained";
/// Code fence used by the decompile extraction.
pub const CODE_FENCE: &str = "```";
/// Label shown when an `ExplainCode` answer has no comment section.
pub const NO_COMMENTS_FOUND_LABEL: &str = "No comments found";
/// Apply-comments label / button.
pub const APPLY_COMMENTS_LABEL: &str = "Apply comments found";
/// Open-decompiled-code label / button.
pub const OPEN_IN_NEW_TAB_LABEL: &str = "Open in new tab";
/// Warning when the merged comment list is empty on Apply.
pub const NO_COMMENTS_FOUND_WARNING: &str = "No comments found!";
/// Warning when the first parsed instruction differs from the zone's
/// first instruction.
pub const UNEXPECTED_COMMENTS_WARNING: &str = "The assistant did not provide the expected comments!";
/// `QueryFunctionNameDialog::IsValidApply` warning text.
pub const SELECT_NAME_WARNING: &str = "Please select a name before applying it";
/// Prefix of the "assistant failed" notification.
pub const NO_RESULT_PREFIX: &str = "The assistant did not provide a result: ";
/// Temporary buffer name for the decompiled code tab.
pub const DECOMPILE_BUFFER_NAME: &str = "temp_decompile.cpp";
/// Temporary folder appended to the object path for the decompile tab.
pub const DECOMPILE_TEMP_FOLDER: &str = "temp_dissasm";
/// Type plugin forced for the decompile tab.
pub const DECOMPILE_TYPE_NAME: &str = "CPP";

/// C++ `trim` (`std::isspace` on both ends).
#[must_use]
pub fn trim(text: &str) -> &str {
    text.trim_matches(is_c_space)
}

/// C++ `rtrim`.
#[must_use]
pub fn rtrim(text: &str) -> &str {
    text.trim_end_matches(is_c_space)
}

/// `std::isspace` in the C locale.
const fn is_c_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
}

/// `FunctionName`: split one answer on `,` and trim every token
/// (`std::getline` keeps empty tokens; a trailing `,` does not add
/// one, exactly like `getline`).
#[must_use]
pub fn parse_function_names(response: &str) -> Vec<String> {
    let mut names: Vec<String> = response.split(',').map(|n| trim(n).to_owned()).collect();
    // `getline` yields no token after a terminating delimiter.
    if response.ends_with(',') {
        names.pop();
    }
    if response.is_empty() {
        names.clear();
    }
    names
}

/// C++ `findMostCommonNames(names, numToReturn)`: the most frequent
/// names (ties broken alphabetically), padded with first-seen names in
/// their original order until `num_to_return` (or the input runs out).
#[must_use]
pub fn find_most_common_names(names: &[String], num_to_return: usize) -> Vec<String> {
    if names.is_empty() || num_to_return == 0 {
        return Vec::new();
    }
    let mut frequency: HashMap<&str, usize> = HashMap::new();
    for name in names {
        let slot = frequency.entry(name.as_str()).or_insert(0);
        *slot = slot.saturating_add(1);
    }
    let mut pairs: Vec<(&str, usize)> = frequency.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let mut result: Vec<String> = pairs
        .iter()
        .take(num_to_return)
        .map(|(name, _)| (*name).to_owned())
        .collect();
    if result.len() < num_to_return {
        for name in names {
            if !result.iter().any(|r| r == name) {
                result.push(name.clone());
                if result.len() == num_to_return {
                    break;
                }
            }
        }
    }
    result
}

/// `FunctionName` retry loop result (`DissasmX86.cpp:2116-2155`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FunctionNameOutcome {
    /// What the `QueryFunctionNameDialog` lists (`namesToShow`).
    pub shown: Vec<String>,
    /// Names parsed from the last response (`names`) — the vector the
    /// C++ rename indexes with the dialog selection.
    pub last_response_names: Vec<String>,
}

impl FunctionNameOutcome {
    /// Builds the outcome from the raw answers of every retry, in
    /// order. `prompt_retries == 1` shows the parsed names as they
    /// came; otherwise the [`find_most_common_names`] top
    /// `names_to_request`.
    #[must_use]
    pub fn from_responses(responses: &[String], names_to_request: usize) -> Self {
        let mut shown: Vec<String> = Vec::new();
        let mut last: Vec<String> = Vec::new();
        for response in responses {
            last = parse_function_names(response);
            shown.extend(last.iter().cloned());
        }
        if responses.len() != 1 {
            shown = find_most_common_names(&shown, names_to_request);
        }
        Self {
            shown,
            last_response_names: last,
        }
    }

    /// The name `TryRenameLine` receives for dialog selection
    /// `selected_index` — C++ indexes `names` (last response), not
    /// `namesToShow`. `None` where C++ would read out of bounds.
    #[must_use]
    pub fn rename_target(&self, selected_index: usize) -> Option<&str> {
        self.last_response_names.get(selected_index).map(String::as_str)
    }
}

/// `ExplainCode`: `(instruction, comment)` pairs from the lines after
/// the [`COMMENTS_ZONE_MARKER`] line; a line without `#` is skipped.
#[must_use]
pub fn parse_comments_zone(response: &str) -> Vec<(String, String)> {
    let mut result: Vec<(String, String)> = Vec::new();
    let mut found_zone = false;
    for line in getline_iter(response) {
        if !found_zone {
            if line.contains(COMMENTS_ZONE_MARKER) {
                found_zone = true;
            }
            continue;
        }
        if let Some(pos) = line.rfind('#') {
            let code_part = line.get(..pos).unwrap_or("");
            let comment_part = line.get(pos.saturating_add(1)..).unwrap_or("");
            result.push((rtrim(code_part).to_owned(), trim(comment_part).to_owned()));
        }
    }
    result
}

/// `std::getline` semantics: `\n`-terminated lines, no trailing empty
/// line for a terminating newline.
fn getline_iter(text: &str) -> impl Iterator<Item = &str> {
    let mut lines: Vec<&str> = text.split('\n').collect();
    if text.ends_with('\n') {
        lines.pop();
    }
    if text.is_empty() {
        lines.clear();
    }
    lines.into_iter()
}

/// The comment merge on Apply (`DissasmX86.cpp:2192-2197`):
/// `"<new>; <existing>"` when the line already had a comment.
#[must_use]
pub fn merge_comment(new_comment: &str, existing: Option<&str>) -> String {
    existing.map_or_else(|| new_comment.to_owned(), |old| format!("{new_comment}; {old}"))
}

/// `ConvertToHighLevel`: the code between the first two fences.
///
/// `DissasmX86.cpp:1920-1941`, minus the C++ off-by-three tail
/// (`codeEnd - codeStart - 3`). `None` when the dialog would disable
/// its *Open* button.
#[must_use]
pub fn extract_decompiled_code(response: &str) -> Option<String> {
    let bytes = response.as_bytes();
    let mut code_start = find_bytes(bytes, CODE_FENCE.as_bytes(), 0)?.checked_add(3)?;
    if code_start.checked_add(4)? >= bytes.len() {
        return None;
    }
    if bytes.get(code_start) == Some(&b'c') {
        code_start = code_start.checked_add(1)?;
    }
    if bytes.get(code_start) == Some(&b'+') {
        code_start = code_start.checked_add(1)?;
    }
    if bytes.get(code_start) == Some(&b'+') {
        code_start = code_start.checked_add(1)?;
    }
    let code_end = find_bytes(bytes, CODE_FENCE.as_bytes(), code_start.checked_add(3)?)?;
    let len = code_end.checked_sub(code_start)?.checked_sub(3)?;
    let slice = bytes.get(code_start..code_start.checked_add(len)?)?;
    Some(String::from_utf8_lossy(slice).into_owned())
}

/// `std::string::find(needle, from)` over bytes.
fn find_bytes(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return (from <= haystack.len()).then_some(from);
    }
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .and_then(|p| p.checked_add(from))
}

/// C++ `wrapText(code, windowWidth)`: word-wraps for the
/// `QueryShowCodeDialog` text area, keeping blank lines as paragraph
/// breaks.
#[must_use]
pub fn wrap_text(code: &str, window_width: usize) -> String {
    let mut wrapped = String::with_capacity(code.len());
    let mut current = String::new();
    for line in getline_iter(code) {
        if line.is_empty() {
            if current.is_empty() {
                wrapped.push('\n');
            } else {
                wrapped.push_str(&current);
                wrapped.push_str("\n\n");
                current.clear();
            }
            continue;
        }
        for word in line.split(is_c_space).filter(|w| !w.is_empty()) {
            if current.len().saturating_add(word.len()).saturating_add(1) > window_width {
                wrapped.push_str(&current);
                wrapped.push('\n');
                current.clear();
            } else if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        wrapped.push_str(&current);
        wrapped.push('\n');
    }
    wrapped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn function_name_split() {
        assert_eq!(
            parse_function_names("  initCrypto , decodePayload,writeConfig\n"),
            strings(&["initCrypto", "decodePayload", "writeConfig"])
        );
        assert_eq!(parse_function_names("a,,b"), strings(&["a", "", "b"]));
        assert_eq!(parse_function_names("a,b,"), strings(&["a", "b"]));
        assert_eq!(parse_function_names(""), Vec::<String>::new());
        assert_eq!(parse_function_names("solo"), strings(&["solo"]));
    }

    #[test]
    fn most_common_names_order_and_padding() {
        let names = strings(&["b", "a", "c", "a", "b", "d"]);
        assert_eq!(find_most_common_names(&names, 2), strings(&["a", "b"]));
        assert_eq!(find_most_common_names(&names, 4), strings(&["a", "b", "c", "d"]));
        assert_eq!(find_most_common_names(&names, 10), strings(&["a", "b", "c", "d"]));
        assert!(find_most_common_names(&names, 0).is_empty());
        assert!(find_most_common_names(&[], 3).is_empty());
    }

    #[test]
    fn outcome_single_retry_and_rename_target_quirk() {
        let one = FunctionNameOutcome::from_responses(&strings(&["x, y, z"]), 5);
        assert_eq!(one.shown, strings(&["x", "y", "z"]));
        assert_eq!(one.rename_target(1), Some("y"));
        assert_eq!(one.rename_target(9), None);

        let two = FunctionNameOutcome::from_responses(&strings(&["x, y", "y, w"]), 5);
        assert_eq!(two.shown, strings(&["y", "w", "x"]));
        // Dialog index 0 shows "y" but the rename reads the last
        // response's names[0] == "y"; index 2 shows "x" yet renames to
        // nothing (out of range in `names`).
        assert_eq!(two.rename_target(0), Some("y"));
        assert_eq!(two.rename_target(1), Some("w"));
        assert_eq!(two.rename_target(2), None);
        assert_eq!(FunctionNameOutcome::from_responses(&[], 5), FunctionNameOutcome::default());
    }

    #[test]
    fn explain_code_parser() {
        let response = "This function copies memory.\nCommentsZoneExplained\npush ebp # save frame\nmov ebp, esp # set up frame  \nno hash here\nret # return #to caller\n";
        assert_eq!(
            parse_comments_zone(response),
            vec![
                ("push ebp".to_owned(), "save frame".to_owned()),
                ("mov ebp, esp".to_owned(), "set up frame".to_owned()),
                ("ret # return".to_owned(), "to caller".to_owned()),
            ]
        );
        assert!(parse_comments_zone("no marker\npush ebp # x").is_empty());
        assert!(parse_comments_zone("CommentsZoneExplained").is_empty());
    }

    #[test]
    fn comment_merge() {
        assert_eq!(merge_comment("new", None), "new");
        assert_eq!(merge_comment("new", Some("old")), "new; old");
    }

    #[test]
    fn decompile_extraction_with_off_by_three_tail() {
        let response = "Sure:\n```c\nint main() { return 0; }\n```\ndone";
        // Between the fences: "\nint main() { return 0; }\n" minus 3.
        assert_eq!(extract_decompiled_code(response), Some("\nint main() { return 0;".to_owned()));
        let response = "```cpp\nvoid f();\n```";
        assert_eq!(extract_decompiled_code(response), Some("pp\nvoid f(".to_owned()));
        let response = "```c++\nvoid f();\n```";
        assert_eq!(extract_decompiled_code(response), Some("\nvoid f(".to_owned()));
        assert_eq!(extract_decompiled_code("no fences"), None);
        assert_eq!(extract_decompiled_code("```"), None, "codeStart + 4 >= size");
        assert_eq!(extract_decompiled_code("```abcd"), None, "codeStart + 4 == size");
        assert_eq!(extract_decompiled_code("```abcde"), None, "no closing fence");
        assert_eq!(extract_decompiled_code("``````x"), None, "codeStart + 4 >= size");
        assert_eq!(extract_decompiled_code("```abc```xyz"), Some(String::new()), "codeEnd - codeStart - 3 == 0");
    }

    #[test]
    fn wrap_text_paragraphs() {
        assert_eq!(wrap_text("one two three four", 9), "one two\nthree\nfour\n");
        assert_eq!(wrap_text("a b\n\nc", 80), "a b\n\nc\n");
        assert_eq!(wrap_text("\n\nx", 80), "\n\nx\n");
        assert_eq!(wrap_text("", 80), "");
        assert_eq!(wrap_text("verylongword", 3), "\nverylongword\n");
    }

    #[test]
    fn trim_helpers() {
        assert_eq!(trim(" \t x y \r\n"), "x y");
        assert_eq!(rtrim("  x  "), "  x");
        assert_eq!(find_bytes(b"abcabc", b"bc", 2), Some(4));
        assert_eq!(find_bytes(b"abc", b"", 3), Some(3));
        assert_eq!(find_bytes(b"abc", b"", 4), None);
    }
}
