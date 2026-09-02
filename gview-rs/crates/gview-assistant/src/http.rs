//! HTTP transport abstraction for the LLM clients.
//!
//! The C++ clients drive `libcurl` directly (`callGPT4oAPI`,
//! `callGeminiAPI`): one `POST`, `Content-Type: application/json`, the
//! response body collected by `WriteCallback` **regardless of the HTTP
//! status** (curl only fails on transport errors), and `is_ok = false`
//! on `CURLE_OK != res`. [`HttpTransport`] captures exactly that
//! contract so the clients can be tested against a
//! [`RecordingTransport`] while production uses [`UreqTransport`].

use std::sync::Mutex;

/// Transport-level failure (the curl `res != CURLE_OK` path).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportError {
    /// Diagnostic text (not shown to users — the clients surface the
    /// verbatim C++ message instead).
    pub message: String,
}

impl TransportError {
    /// Wraps a diagnostic.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TransportError {}

/// One JSON `POST`.
pub trait HttpTransport: Send + Sync {
    /// Posts `body` to `url` with the given headers and returns the
    /// raw response body, whatever the HTTP status code.
    ///
    /// # Errors
    ///
    /// [`TransportError`] only for connection / TLS / I/O failures.
    fn post_json(&self, url: &str, headers: &[(&str, &str)], body: &str) -> Result<String, TransportError>;
}

impl<T: HttpTransport + ?Sized> HttpTransport for std::sync::Arc<T> {
    fn post_json(&self, url: &str, headers: &[(&str, &str)], body: &str) -> Result<String, TransportError> {
        (**self).post_json(url, headers, body)
    }
}

/// A captured request (for tests and the UI "Show last prompt"
/// button).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedRequest {
    /// Target URL.
    pub url: String,
    /// Headers in send order.
    pub headers: Vec<(String, String)>,
    /// JSON body.
    pub body: String,
}

/// Canned-response transport that records every request.
#[derive(Debug)]
pub struct RecordingTransport {
    response: Result<String, TransportError>,
    requests: Mutex<Vec<RecordedRequest>>,
}

impl RecordingTransport {
    /// Always answers `response`.
    #[must_use]
    pub const fn new(response: Result<String, TransportError>) -> Self {
        Self {
            response,
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Answers with a successful body.
    #[must_use]
    pub fn responding(body: impl Into<String>) -> Self {
        Self::new(Ok(body.into()))
    }

    /// Fails every request (curl `res != CURLE_OK`).
    #[must_use]
    pub fn failing() -> Self {
        Self::new(Err(TransportError::new("simulated transport failure")))
    }

    /// Every request seen so far, oldest first.
    #[must_use]
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// The most recent request.
    #[must_use]
    pub fn last_request(&self) -> Option<RecordedRequest> {
        self.requests.lock().ok().and_then(|g| g.last().cloned())
    }
}

impl HttpTransport for RecordingTransport {
    fn post_json(&self, url: &str, headers: &[(&str, &str)], body: &str) -> Result<String, TransportError> {
        let record = RecordedRequest {
            url: url.to_owned(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.to_owned(),
        };
        if let Ok(mut guard) = self.requests.lock() {
            guard.push(record);
        }
        self.response.clone()
    }
}

/// Production transport over `ureq` (blocking, rustls). Mirrors curl:
/// HTTP error statuses are **not** transport failures — their body is
/// returned for the JSON parsers to reject.
#[cfg(feature = "http-client")]
#[derive(Clone, Debug)]
pub struct UreqTransport {
    agent: ureq::Agent,
}

#[cfg(feature = "http-client")]
impl UreqTransport {
    /// Agent with `http_status_as_error(false)` and default timeouts.
    #[must_use]
    pub fn new() -> Self {
        let config = ureq::config::Config::builder()
            .http_status_as_error(false)
            .build();
        Self {
            agent: config.new_agent(),
        }
    }
}

#[cfg(feature = "http-client")]
impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "http-client")]
impl HttpTransport for UreqTransport {
    fn post_json(&self, url: &str, headers: &[(&str, &str)], body: &str) -> Result<String, TransportError> {
        let mut request = self.agent.post(url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut response = request
            .send(body)
            .map_err(|e| TransportError::new(e.to_string()))?;
        response
            .body_mut()
            .read_to_string()
            .map_err(|e| TransportError::new(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_transport_captures_requests_in_order() {
        let t = RecordingTransport::responding("{}");
        assert!(t.last_request().is_none());
        let out = t.post_json("https://a", &[("Content-Type", "application/json")], "{\"x\":1}");
        assert_eq!(out, Ok("{}".to_owned()));
        let _ = t.post_json("https://b", &[], "");
        let reqs = t.requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs.first().map(|r| r.url.as_str()), Some("https://a"));
        assert_eq!(
            reqs.first().map(|r| r.headers.clone()),
            Some(vec![("Content-Type".to_owned(), "application/json".to_owned())])
        );
        assert_eq!(t.last_request().map(|r| r.url), Some("https://b".to_owned()));
    }

    #[test]
    fn failing_transport_and_arc_forwarding() {
        let t = std::sync::Arc::new(RecordingTransport::failing());
        let err = t.post_json("u", &[], "b").expect_err("must fail");
        assert_eq!(err.to_string(), "simulated transport failure");
        assert_eq!(t.requests().len(), 1);
    }

    #[cfg(feature = "http-client")]
    #[test]
    fn ureq_transport_constructs() {
        let _t = UreqTransport::default();
    }
}
