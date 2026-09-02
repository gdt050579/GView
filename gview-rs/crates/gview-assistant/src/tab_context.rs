//! Smart Assistants tab chat context (`QueryInterface.cpp`
//! `computeRelevanceScore`, `GetFinalContext`, `BuildChatContext`;
//! spec §3).
//!
//! What the model receives for a tab question is **not** the user's
//! text: it is the type plugin's `GetSmartAssistantContext` JSON,
//! ranked field-by-field against the user's text and re-serialized.
//! The user text only steers the ranking (and is what the UI shows).
//!
//! C++ details reproduced:
//! - scoring: `+10` for the field name appearing verbatim in the
//!   prompt, `+5` for the first matching synonym (case-sensitive
//!   substring search, `std::string::find`);
//! - fields are visited in nlohmann's `std::map` order (alphabetical),
//!   sorted by score descending (stable here; C++ `std::sort` is
//!   unspecified among equal scores) and copied as `value.dump()`
//!   strings — so a string value keeps its quotes and a number becomes
//!   text — until the **key count** reaches `maxPromptSize`
//!   (`GetCharacterLimit()`, 1024): the key that hits the limit is
//!   erased again, hence at most `maxPromptSize - 1` keys survive;
//! - the result is `dump()`ed from a `std::map`-backed object, i.e.
//!   keys come out alphabetically whatever the ranking;
//! - the synonym table names `FileName` / `Author` / `CreationDate`,
//!   keys no plugin emits (plugins emit `Name`) — kept as-is;
//! - fallback context on plugin failure: `{"ERR":"failed to get data"}`.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::CHARACTER_LIMIT;

/// `synonymMap` (`QueryInterface.cpp:379-383`).
pub const SYNONYM_MAP: &[(&str, &[&str])] = &[
    ("FileName", &["document", "file", "name"]),
    ("ImagesCount", &["pictures", "photos", "images", "graphics"]),
    ("FileSize", &["size", "memory", "storage"]),
    ("Author", &["writer", "creator", "author"]),
    ("CreationDate", &["date", "created", "creation"]),
];

/// Score for a direct field-name hit.
pub const DIRECT_MATCH_SCORE: i32 = 10;
/// Score for the first synonym hit.
pub const SYNONYM_MATCH_SCORE: i32 = 5;
/// Fallback context key when the type plugin yields no context.
pub const ERR_KEY: &str = "ERR";
/// Fallback context value (spec §3.6).
pub const ERR_FALLBACK: &str = "failed to get data";

/// `computeRelevanceScore(fieldName, userPrompt)`.
#[must_use]
pub fn compute_relevance_score(field_name: &str, user_prompt: &str) -> i32 {
    let mut score = 0i32;
    if user_prompt.contains(field_name) {
        score = score.saturating_add(DIRECT_MATCH_SCORE);
    }
    if let Some((_, synonyms)) = SYNONYM_MAP.iter().find(|(name, _)| *name == field_name) {
        if synonyms.iter().any(|s| user_prompt.contains(s)) {
            score = score.saturating_add(SYNONYM_MATCH_SCORE);
        }
    }
    score
}

/// Ranked `(key, score)` pairs, alphabetical input order, stable sort
/// by score descending.
#[must_use]
pub fn rank_fields(context: &Map<String, Value>, user_prompt: &str) -> Vec<(String, i32)> {
    let mut scored: Vec<(String, i32)> = context
        .iter()
        .map(|(key, _)| (key.clone(), compute_relevance_score(key, user_prompt)))
        .collect();
    // `Map` iterates alphabetically (BTreeMap-backed, like nlohmann's
    // std::map); make it explicit so a `preserve_order` build behaves
    // identically.
    scored.sort_by(|a, b| a.0.cmp(&b.0));
    scored.sort_by_key(|(_, score)| core::cmp::Reverse(*score));
    scored
}

/// `GetFinalContext(contextualData, userPrompt, maxPromptSize)`:
/// serialized JSON object of `key → value.dump()` strings.
#[must_use]
pub fn get_final_context(context: &Map<String, Value>, user_prompt: &str, max_prompt_size: u32) -> String {
    let limit = max_prompt_size as usize;
    let mut result: BTreeMap<&str, String> = BTreeMap::new();
    for (key, _) in rank_fields(context, user_prompt) {
        let Some((stored_key, value)) = context.get_key_value(key.as_str()) else {
            continue;
        };
        result.insert(stored_key.as_str(), value.to_string());
        if result.len() >= limit {
            result.remove(stored_key.as_str());
            break;
        }
    }
    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_owned())
}

/// The `{"ERR":"failed to get data"}` fallback object.
#[must_use]
pub fn fallback_context() -> Map<String, Value> {
    let mut map = Map::new();
    map.insert(ERR_KEY.to_owned(), Value::String(ERR_FALLBACK.to_owned()));
    map
}

/// `BuildChatContext(prompt, displayPrompt, assistantIndex)`.
///
/// Ranks the plugin context (or the fallback when the plugin produced
/// nothing or a non-object) and returns the text that is sent as the
/// model prompt. `user_prompt` is never part of the result.
#[must_use]
pub fn build_chat_context(plugin_context: Option<&Value>, user_prompt: &str, character_limit: u32) -> String {
    match plugin_context {
        Some(Value::Object(map)) => get_final_context(map, user_prompt, character_limit),
        _ => get_final_context(&fallback_context(), user_prompt, character_limit),
    }
}

/// [`build_chat_context`] with the bundled assistants' limit
/// ([`CHARACTER_LIMIT`]).
#[must_use]
pub fn build_chat_context_default(plugin_context: Option<&Value>, user_prompt: &str) -> String {
    build_chat_context(plugin_context, user_prompt, CHARACTER_LIMIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        match v {
            Value::Object(m) => m,
            _ => panic!("object expected"),
        }
    }

    #[test]
    fn synonym_scoring() {
        assert_eq!(compute_relevance_score("FileSize", "FileSize? what size is it"), 15);
        assert_eq!(compute_relevance_score("FileSize", "FileSize? how big is the file"), 10);
        assert_eq!(compute_relevance_score("FileSize", "how big is the file size"), 5);
        assert_eq!(compute_relevance_score("FileSize", "memory and storage"), 5);
        assert_eq!(compute_relevance_score("FileSize", "filesize"), 5, "name miss (case-sensitive), synonym `size` hit");
        assert_eq!(compute_relevance_score("FileSize", "FILESIZE"), 0, "case-sensitive");
        assert_eq!(compute_relevance_score("ImagesCount", "show pictures"), 5);
        assert_eq!(compute_relevance_score("Name", "what is the Name"), 10);
        assert_eq!(compute_relevance_score("Name", "what is the name"), 0, "Name has no synonyms");
        assert_eq!(compute_relevance_score("Author", "who created it"), 0);
        assert_eq!(compute_relevance_score("Author", "the writer"), 5);
    }

    #[test]
    fn ranking_is_stable_and_alphabetical_among_ties() {
        let ctx = obj(json!({"Zeta": 1, "Alpha": 2, "FileSize": 3, "Name": "x"}));
        let ranked = rank_fields(&ctx, "Name and size");
        let keys: Vec<&str> = ranked.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["Name", "FileSize", "Alpha", "Zeta"]);
        assert_eq!(ranked.first().map(|r| r.1), Some(10));
    }

    #[test]
    fn values_are_dumped_strings_and_keys_sorted() {
        let ctx = obj(json!({"Name": "a.exe", "ContentSize": 1234, "Exports": ["f"]}));
        let out = get_final_context(&ctx, "anything", 1024);
        assert_eq!(out, "{\"ContentSize\":\"1234\",\"Exports\":\"[\\\"f\\\"]\",\"Name\":\"\\\"a.exe\\\"\"}");
    }

    #[test]
    fn key_limit_keeps_at_most_limit_minus_one_ranked_keys() {
        let mut map = Map::new();
        for i in 0..1030u32 {
            map.insert(format!("k{i:04}"), Value::from(i));
        }
        let out = get_final_context(&map, "", 1024);
        let parsed: Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(parsed.as_object().map(Map::len), Some(1023));

        // With a tiny limit the highest-ranked survive.
        let ctx = obj(json!({"Zeta": 1, "FileSize": 2, "Name": 3, "Beta": 4}));
        let out = get_final_context(&ctx, "Name size", 3);
        assert_eq!(out, "{\"FileSize\":\"2\",\"Name\":\"3\"}");
        assert_eq!(get_final_context(&ctx, "", 1), "{}");
        assert_eq!(get_final_context(&ctx, "", 0), "{}");
        assert_eq!(get_final_context(&Map::new(), "", 1024), "{}");
    }

    #[test]
    fn user_prompt_not_in_payload() {
        let ctx = json!({"Name": "sample.pe", "ContentSize": 10});
        let question = "Is this file malicious?";
        let out = build_chat_context(Some(&ctx), question, 1024);
        assert!(!out.contains(question));
        assert!(!out.contains("malicious"));
        assert_eq!(out, build_chat_context_default(Some(&ctx), question));
        assert_eq!(out, "{\"ContentSize\":\"10\",\"Name\":\"\\\"sample.pe\\\"\"}");
    }

    #[test]
    fn fallback_when_plugin_fails_or_returns_non_object() {
        assert_eq!(build_chat_context(None, "q", 1024), "{\"ERR\":\"\\\"failed to get data\\\"\"}");
        assert_eq!(build_chat_context(Some(&json!([1])), "q", 1024), "{\"ERR\":\"\\\"failed to get data\\\"\"}");
        assert_eq!(fallback_context().get(ERR_KEY), Some(&Value::String(ERR_FALLBACK.to_owned())));
    }
}
