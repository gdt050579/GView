//! Gemini 1.5 Pro client (`SmartAssistantPlugin.cpp`
//! `GeminiPro1_5SmartAssistant`, `callGeminiAPI`, `parseGeminiResponse`;
//! spec §2.2).
//!
//! **Request shape (C++ wins over spec §2.2).** The C++ payload is built
//! with nlohmann brace-elision:
//!
//! ```cpp
//! json payload = { { "contents", { { "parts", { { "text", prompt } } } } } };
//! ```
//!
//! `{ {"text", prompt} }` is a one-pair list → an *object*, and the same
//! rule applies to `parts` and `contents`, so the wire format is
//!
//! ```json
//! {"contents":{"parts":{"text":"<prompt>"}}}
//! ```
//!
//! (objects, not the arrays the spec sketches). This port reproduces
//! the C++ bytes; [`build_request_body`] is the single place to change
//! if the endpoint ever rejects the object form.
//!
//! Response: first `candidates[i].content.parts[0].text`. No system
//! message. The URL carries the key as a query parameter, appended
//! without escaping, exactly like the C++ string concatenation.

use serde_json::{json, Value};

use crate::http::HttpTransport;
use crate::{AssistantError, SmartAssistantProvider, ERROR_CALLING_GEMINI_API, NO_RESPONSE_FOUND};

/// Endpoint prefix; the API key is appended verbatim.
pub const GEMINI_URL_PREFIX: &str =
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent?key=";
/// Model slug embedded in [`GEMINI_URL_PREFIX`].
pub const GEMINI_MODEL: &str = "gemini-1.5-pro-latest";
/// `GetSmartAssistantName()` / INI key.
pub const GEMINI_NAME: &str = "GeminiPro1.5";
/// `GetSmartAssistantDescription()`.
pub const GEMINI_DESCRIPTION: &str = "GeminiPro1.5 is a smart assistant that can help you with various questions";
/// `catch (...)` branch of `parseGeminiResponse`.
pub const ERROR_GETTING_PARSING_RESPONSE: &str = "Error getting/parsing response!";

/// Full request URL for an API key.
#[must_use]
pub fn request_url(api_key: &str) -> String {
    format!("{GEMINI_URL_PREFIX}{api_key}")
}

/// Builds the request body exactly as the C++ `payload.dump()` (see
/// the module docs for why these are objects).
#[must_use]
pub fn build_request_body(prompt: &str) -> String {
    json!({ "contents": { "parts": { "text": prompt } } }).to_string()
}

/// nlohmann `size()`: `null` → 0, containers → element count, scalars
/// → 1.
fn nlohmann_size(value: &Value) -> usize {
    match value {
        Value::Null => 0,
        Value::Array(a) => a.len(),
        Value::Object(o) => o.len(),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => 1,
    }
}

/// `value[i]` on a non-const json: arrays index, `null` becomes an
/// array (out-of-range reads yield `null`), anything else throws.
fn index_num(value: &Value, i: usize) -> Option<&Value> {
    match value {
        Value::Array(items) => Some(items.get(i).unwrap_or(&Value::Null)),
        Value::Null => Some(&Value::Null),
        _ => None,
    }
}

/// `value["key"]` on a non-const json: objects look up (missing →
/// `null`), `null` becomes an object (→ `null`), anything else throws.
fn index_str<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => Some(map.get(key).unwrap_or(&Value::Null)),
        Value::Null => Some(&Value::Null),
        _ => None,
    }
}

/// `parseGeminiResponse`: `Ok(text)` or the verbatim failure text.
///
/// # Errors
///
/// [`NO_RESPONSE_FOUND`] when no candidate has a part, and
/// [`ERROR_GETTING_PARSING_RESPONSE`] for syntax errors or any shape
/// that makes the C++ `operator[]` / string conversion throw.
pub fn parse_response(raw: &str) -> Result<String, String> {
    walk(raw).map_err(|failure| match failure {
        Failure::NoResponse => NO_RESPONSE_FOUND.to_owned(),
        Failure::Exception => ERROR_GETTING_PARSING_RESPONSE.to_owned(),
    })
}

enum Failure {
    NoResponse,
    Exception,
}

fn walk(raw: &str) -> Result<String, Failure> {
    let data: Value = serde_json::from_str(raw).map_err(|_| Failure::Exception)?;
    let candidates = index_str(&data, "candidates").ok_or(Failure::Exception)?;
    let answers_count = nlohmann_size(candidates);
    for i in 0..answers_count {
        let answer = index_num(candidates, i).ok_or(Failure::Exception)?;
        let content = index_str(answer, "content").ok_or(Failure::Exception)?;
        let parts = index_str(content, "parts").ok_or(Failure::Exception)?;
        if nlohmann_size(parts) == 0 {
            continue;
        }
        // Only `j == 0` is ever read: the C++ loop returns on its first
        // iteration.
        let part = index_num(parts, 0).ok_or(Failure::Exception)?;
        let text = index_str(part, "text").ok_or(Failure::Exception)?;
        return match text {
            Value::String(s) => Ok(s.clone()),
            _ => Err(Failure::Exception),
        };
    }
    Err(Failure::NoResponse)
}

/// `GeminiPro1_5SmartAssistant`.
pub struct GeminiAssistant<T: HttpTransport> {
    transport: T,
    token: String,
}

impl<T: HttpTransport> GeminiAssistant<T> {
    /// Client without a token (set by [`SmartAssistantProvider::receive_config_token`]).
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            token: String::new(),
        }
    }

    /// The configured API key.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// `callGeminiAPI`: raw response body, or the transport failure.
    ///
    /// # Errors
    ///
    /// Propagates the transport error (curl `res != CURLE_OK`).
    pub fn call_api(&self, prompt: &str) -> Result<String, crate::http::TransportError> {
        let headers = [("Content-Type", "application/json")];
        self.transport
            .post_json(&request_url(&self.token), &headers, &build_request_body(prompt))
    }
}

impl<T: HttpTransport> SmartAssistantProvider for GeminiAssistant<T> {
    fn name(&self) -> &str {
        GEMINI_NAME
    }

    fn description(&self) -> &str {
        GEMINI_DESCRIPTION
    }

    fn receive_config_token(&mut self, token: &str) {
        token.clone_into(&mut self.token);
    }

    fn ask(&self, prompt: &str, _display_prompt: &str) -> Result<String, AssistantError> {
        let raw = self
            .call_api(prompt)
            .map_err(|_| AssistantError::new(ERROR_CALLING_GEMINI_API))?;
        parse_response(&raw).map_err(AssistantError::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::RecordingTransport;
    use std::sync::Arc;

    #[test]
    fn url_model_slug_and_key() {
        let url = request_url("AIza-key");
        assert_eq!(
            url,
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent?key=AIza-key"
        );
        assert!(url.contains(GEMINI_MODEL));
        assert!(url.ends_with("?key=AIza-key"));
    }

    #[test]
    fn request_body_matches_cpp_brace_elision() {
        assert_eq!(
            build_request_body("hello"),
            "{\"contents\":{\"parts\":{\"text\":\"hello\"}}}"
        );
    }

    #[test]
    fn parses_candidates_parts_text() {
        let raw = r#"{"candidates":[{"content":{"parts":[{"text":"first"},{"text":"second"}],"role":"model"}}]}"#;
        assert_eq!(parse_response(raw), Ok("first".to_owned()));
        // First candidate without parts is skipped.
        let raw = r#"{"candidates":[{"content":{"parts":[]}},{"content":{"parts":[{"text":"later"}]}}]}"#;
        assert_eq!(parse_response(raw), Ok("later".to_owned()));
        // Candidates lacking `content` at all are skipped too.
        let raw = r#"{"candidates":[{"finishReason":"SAFETY"},{"content":{"parts":[{"text":"ok"}]}}]}"#;
        assert_eq!(parse_response(raw), Ok("ok".to_owned()));
    }

    #[test]
    fn no_response_cases() {
        for raw in ["{}", r#"{"candidates":[]}"#, r#"{"candidates":null}"#, r#"{"candidates":[{"content":{"parts":[]}}]}"#, r#"{"candidates":[null]}"#] {
            assert_eq!(parse_response(raw), Err(NO_RESPONSE_FOUND.to_owned()), "{raw}");
        }
    }

    #[test]
    fn exception_cases() {
        for raw in [
            "nope",
            "[1]",
            r#"{"candidates":"x"}"#,
            r#"{"candidates":{"a":1}}"#,
            r#"{"candidates":[5]}"#,
            r#"{"candidates":[{"content":"s"}]}"#,
            r#"{"candidates":[{"content":{"parts":{"k":1}}}]}"#,
            r#"{"candidates":[{"content":{"parts":"t"}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{"text":3}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[null]}}]}"#,
        ] {
            assert_eq!(parse_response(raw), Err(ERROR_GETTING_PARSING_RESPONSE.to_owned()), "{raw}");
        }
    }

    #[test]
    fn ask_posts_json_without_system_message() {
        let transport = Arc::new(RecordingTransport::responding(
            r#"{"candidates":[{"content":{"parts":[{"text":"answer"}]}}]}"#,
        ));
        let mut gemini = GeminiAssistant::new(Arc::clone(&transport));
        gemini.receive_config_token("KEY");
        assert_eq!(gemini.token(), "KEY");
        assert_eq!(gemini.name(), "GeminiPro1.5");
        assert_eq!(gemini.description(), GEMINI_DESCRIPTION);
        assert_eq!(gemini.character_limit(), 1024);
        assert_eq!(gemini.ask("q", "shown"), Ok("answer".to_owned()));
        let req = transport.last_request().expect("recorded");
        assert_eq!(req.url, request_url("KEY"));
        assert_eq!(req.headers, vec![("Content-Type".to_owned(), "application/json".to_owned())]);
        assert_eq!(req.body, "{\"contents\":{\"parts\":{\"text\":\"q\"}}}");
        assert!(!req.body.contains("system"));
    }

    #[test]
    fn transport_and_parse_failures() {
        let gemini = GeminiAssistant::new(RecordingTransport::failing());
        assert_eq!(gemini.ask("p", "d"), Err(AssistantError::new("Error calling Gemini API!")));
        let gemini = GeminiAssistant::new(RecordingTransport::responding(r#"{"error":{"code":400}}"#));
        assert_eq!(gemini.ask("p", "d"), Err(AssistantError::new(NO_RESPONSE_FOUND)));
    }
}
