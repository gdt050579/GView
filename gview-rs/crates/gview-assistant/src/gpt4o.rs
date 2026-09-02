//! GPT-4o client (`SmartAssistantPlugin.cpp` `ChatGPT4oAssistant`,
//! `callGPT4oAPI`, `parseGPT4oResponse`; spec §2.1).
//!
//! Request (nlohmann `dump()` → compact, keys sorted):
//!
//! ```json
//! {"messages":[{"content":"You are a helpful assistant.","role":"system"},
//!              {"content":"<prompt>","role":"user"}],"model":"gpt-4o"}
//! ```
//!
//! Response: `choices[0].message.content`.
//!
//! Parity quirks kept verbatim:
//! - a transport failure reports `"Error calling Gemini API!"`
//!   (`SmartAssistantPlugin.cpp:192-194`, spec §3.5);
//! - the JSON error branch of `parseGPT4oResponse` prefixes the
//!   library's exception text with `"Error parsing response: "`. The
//!   nlohmann `type_error` texts are reproduced for the shapes that
//!   code can hit; syntax errors carry the `serde_json` message instead
//!   of nlohmann's `parse_error.101` wording.

use serde_json::{json, Value};

use crate::http::HttpTransport;
use crate::{AssistantError, SmartAssistantProvider, ERROR_CALLING_GEMINI_API, NO_RESPONSE_FOUND};

/// `OpenAI` chat completions endpoint.
pub const GPT4O_URL: &str = "https://api.openai.com/v1/chat/completions";
/// `"model"` field (C++ comment: currently points to `gpt-4o-2024-08-06`).
pub const GPT4O_MODEL: &str = "gpt-4o";
/// `GetSmartAssistantName()` / INI key.
pub const GPT4O_NAME: &str = "GPT4o";
/// `GetSmartAssistantDescription()`.
pub const GPT4O_DESCRIPTION: &str = "GPT4o is a smart assistant that can help you with various questions";
/// System message (verbatim).
pub const GPT4O_SYSTEM_MESSAGE: &str = "You are a helpful assistant.";
/// Prefix of the exception branch of `parseGPT4oResponse`.
pub const ERROR_PARSING_RESPONSE_PREFIX: &str = "Error parsing response: ";
/// `catch (...)` branch of `parseGPT4oResponse` (unreachable in
/// practice, kept for completeness).
pub const UNKNOWN_PARSE_ERROR: &str = "Unknown error while parsing response!";

/// Builds the request body exactly as the C++ `payload.dump()`.
#[must_use]
pub fn build_request_body(prompt: &str) -> String {
    json!({
        "model": GPT4O_MODEL,
        "messages": [
            { "role": "system", "content": GPT4O_SYSTEM_MESSAGE },
            { "role": "user", "content": prompt },
        ],
    })
    .to_string()
}

/// nlohmann `type_error.305` text for `operator[]` misuse.
fn type_error_305(argument: &str, value: &Value) -> String {
    format!(
        "[json.exception.type_error.305] cannot use operator[] with a {argument} argument with {}",
        nlohmann_type_name(value)
    )
}

/// nlohmann `type_name()`.
const fn nlohmann_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// nlohmann `json::empty()`: `null` → true, containers → no elements,
/// scalars → false.
fn nlohmann_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

/// Non-const `operator[](const char*)`: on `null` the value becomes an
/// object and the lookup yields `null`; on an object a missing key
/// yields `null`; anything else throws `type_error.305`.
fn index_str<'a>(value: &'a Value, key: &str) -> Result<&'a Value, String> {
    match value {
        Value::Null => Ok(&Value::Null),
        Value::Object(map) => Ok(map.get(key).unwrap_or(&Value::Null)),
        other => Err(type_error_305("string", other)),
    }
}

/// `parseGPT4oResponse`: `Ok(content)` or the verbatim failure text.
///
/// # Errors
///
/// [`NO_RESPONSE_FOUND`] when `choices` is absent or empty (or the
/// payload is not an object), otherwise
/// `"Error parsing response: <reason>"`.
pub fn parse_response(raw: &str) -> Result<String, String> {
    let data: Value = serde_json::from_str(raw).map_err(|e| format!("{ERROR_PARSING_RESPONSE_PREFIX}{e}"))?;
    let choices = match &data {
        Value::Object(map) => map.get("choices"),
        _ => None,
    };
    let Some(choices) = choices else {
        return Err(NO_RESPONSE_FOUND.to_owned());
    };
    if nlohmann_empty(choices) {
        return Err(NO_RESPONSE_FOUND.to_owned());
    }
    extract_content(choices).map_err(|reason| format!("{ERROR_PARSING_RESPONSE_PREFIX}{reason}"))
}

/// `data["choices"][0]["message"]["content"].get<std::string>()`.
fn extract_content(choices: &Value) -> Result<String, String> {
    let first = match choices {
        Value::Array(items) => items.first().unwrap_or(&Value::Null),
        // `operator[](size_type)` on a non-array non-null throws.
        other => return Err(type_error_305("numeric", other)),
    };
    let message = index_str(first, "message")?;
    let content = index_str(message, "content")?;
    match content {
        Value::String(s) => Ok(s.clone()),
        other => Err(format!(
            "[json.exception.type_error.302] type must be string, but is {}",
            nlohmann_type_name(other)
        )),
    }
}

/// `ChatGPT4oAssistant`.
pub struct Gpt4oAssistant<T: HttpTransport> {
    transport: T,
    token: String,
}

impl<T: HttpTransport> Gpt4oAssistant<T> {
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

    /// `callGPT4oAPI`: raw response body, or the transport failure.
    ///
    /// # Errors
    ///
    /// Propagates the transport error (curl `res != CURLE_OK`).
    pub fn call_api(&self, prompt: &str) -> Result<String, crate::http::TransportError> {
        let auth = format!("Bearer {}", self.token);
        let headers = [("Content-Type", "application/json"), ("Authorization", auth.as_str())];
        self.transport
            .post_json(GPT4O_URL, &headers, &build_request_body(prompt))
    }
}

impl<T: HttpTransport> SmartAssistantProvider for Gpt4oAssistant<T> {
    fn name(&self) -> &str {
        GPT4O_NAME
    }

    fn description(&self) -> &str {
        GPT4O_DESCRIPTION
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
    fn request_body_matches_cpp_dump() {
        assert_eq!(
            build_request_body("hi \"there\""),
            "{\"messages\":[{\"content\":\"You are a helpful assistant.\",\"role\":\"system\"},{\"content\":\"hi \\\"there\\\"\",\"role\":\"user\"}],\"model\":\"gpt-4o\"}"
        );
    }

    #[test]
    fn gpt_response_parse() {
        let raw = r#"{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"Hello!"},"finish_reason":"stop"}]}"#;
        assert_eq!(parse_response(raw), Ok("Hello!".to_owned()));
    }

    #[test]
    fn missing_or_empty_choices_is_no_response() {
        assert_eq!(parse_response("{}"), Err(NO_RESPONSE_FOUND.to_owned()));
        assert_eq!(parse_response(r#"{"choices":[]}"#), Err(NO_RESPONSE_FOUND.to_owned()));
        assert_eq!(parse_response(r#"{"choices":null}"#), Err(NO_RESPONSE_FOUND.to_owned()));
        assert_eq!(parse_response(r#"{"choices":{}}"#), Err(NO_RESPONSE_FOUND.to_owned()));
        assert_eq!(parse_response("[1,2]"), Err(NO_RESPONSE_FOUND.to_owned()));
        assert_eq!(
            parse_response(r#"{"error":{"message":"Incorrect API key"}}"#),
            Err(NO_RESPONSE_FOUND.to_owned())
        );
    }

    #[test]
    fn type_errors_carry_nlohmann_wording() {
        assert_eq!(
            parse_response(r#"{"choices":[{"message":{}}]}"#),
            Err("Error parsing response: [json.exception.type_error.302] type must be string, but is null".to_owned())
        );
        assert_eq!(
            parse_response(r#"{"choices":[{"message":{"content":5}}]}"#),
            Err("Error parsing response: [json.exception.type_error.302] type must be string, but is number".to_owned())
        );
        assert_eq!(
            parse_response(r#"{"choices":"abc"}"#),
            Err("Error parsing response: [json.exception.type_error.305] cannot use operator[] with a numeric argument with string".to_owned())
        );
        assert_eq!(
            parse_response(r#"{"choices":{"a":1}}"#),
            Err("Error parsing response: [json.exception.type_error.305] cannot use operator[] with a numeric argument with object".to_owned())
        );
        assert_eq!(
            parse_response(r#"{"choices":[7]}"#),
            Err("Error parsing response: [json.exception.type_error.305] cannot use operator[] with a string argument with number".to_owned())
        );
        assert_eq!(
            parse_response(r#"{"choices":[{"message":[1]}]}"#),
            Err("Error parsing response: [json.exception.type_error.305] cannot use operator[] with a string argument with array".to_owned())
        );
    }

    #[test]
    fn syntax_error_is_prefixed() {
        let err = parse_response("not json").expect_err("must fail");
        assert!(err.starts_with(ERROR_PARSING_RESPONSE_PREFIX));
    }

    #[test]
    fn ask_sends_headers_and_system_message_verbatim() {
        let transport = Arc::new(RecordingTransport::responding(
            r#"{"choices":[{"message":{"content":"42\n"}}]}"#,
        ));
        let mut gpt = Gpt4oAssistant::new(Arc::clone(&transport));
        gpt.receive_config_token("sk-test");
        assert_eq!(gpt.token(), "sk-test");
        assert_eq!(gpt.name(), "GPT4o");
        assert_eq!(gpt.description(), GPT4O_DESCRIPTION);
        assert_eq!(gpt.character_limit(), 1024);

        assert_eq!(gpt.ask("What?", "shown"), Ok("42\n".to_owned()));
        let req = transport.last_request().expect("request recorded");
        assert_eq!(req.url, GPT4O_URL);
        assert_eq!(
            req.headers,
            vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Authorization".to_owned(), "Bearer sk-test".to_owned())
            ]
        );
        assert!(req.body.contains("\"content\":\"You are a helpful assistant.\""));
        assert!(req.body.contains("\"content\":\"What?\""));
        assert!(!req.body.contains("shown"), "display prompt never leaves the UI");
    }

    #[test]
    fn transport_failure_uses_gemini_wording() {
        let gpt = Gpt4oAssistant::new(RecordingTransport::failing());
        assert_eq!(gpt.ask("p", "d"), Err(AssistantError::new("Error calling Gemini API!")));
    }

    #[test]
    fn http_error_body_becomes_parse_failure() {
        let gpt = Gpt4oAssistant::new(RecordingTransport::responding(
            r#"{"error":{"message":"Incorrect API key provided"}}"#,
        ));
        assert_eq!(gpt.ask("p", "d"), Err(AssistantError::new(NO_RESPONSE_FOUND)));
    }
}
