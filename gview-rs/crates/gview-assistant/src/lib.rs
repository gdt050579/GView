//! `GView` `SmartAssistant` LLM engine (spec `06_SMART_ASSISTANT_AND_LLM`).
//!
//! Port of the three C++ call paths:
//!
//! | C++ | Rust |
//! |-----|------|
//! | `SmartAssistantPlugin.cpp` (`callGPT4oAPI`, `callGeminiAPI`) | [`gpt4o`], [`gemini`] over [`http::HttpTransport`] |
//! | `QueryInterface.cpp` (`SmartAssistantPromptInterfaceProxy`) | [`AssistantRegistry`], [`tab_context`] |
//! | `DissasmViewer` (`QuerySmartAssistant`, `QuerySmartAssistantX86X64`) | [`disasm_prompt`], [`disasm_parse`] |
//! | `SummaryController.cpp` (HDF summary) | [`hdf_summary`] |
//!
//! The registry mirrors `SmartAssistantPromptInterfaceProxy`: assistant
//! registration with the C++ name checks, `[SmartAssistants]` INI token
//! distribution (`Start`), the preferred-assistant selection state
//! machine (`GetSmartAssistantInterface`) and the `AskSmartAssistant`
//! proxy that strips one trailing newline from every answer.
//!
//! No UI lives here: dialogs, tabs and background workers are wired by
//! the application crate (`APPCUI_RS_UI_AND_ASYNC_GUIDE` §5.2). All
//! network I/O goes through [`http::HttpTransport`] so every client can
//! be exercised against a recorded transport in tests.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod config;
pub mod disasm_parse;
pub mod disasm_prompt;
pub mod gemini;
pub mod gpt4o;
pub mod hdf_summary;
pub mod http;
pub mod tab_context;

#[cfg(test)]
mod cpp_parity_quirks;

pub use config::AssistantConfig;
pub use http::HttpTransport;

/// `GetCharacterLimit()` of both bundled assistants
/// (`SmartAssistantPlugin.cpp`, spec §2.3).
pub const CHARACTER_LIMIT: u32 = 1024;

/// INI section holding assistant tokens and `PromptRetries`
/// (`SMART_ASSISTANTS_CONFIGURATION_NAME`).
pub const SMART_ASSISTANTS_SECTION: &str = "SmartAssistants";

/// INI key for the `FunctionName` retry count (spec §2.4).
pub const PROMPT_RETRIES_KEY: &str = "PromptRetries";

/// Transport-failure text returned by **both** assistants — the GPT-4o
/// path copies the Gemini wording (`SmartAssistantPlugin.cpp:192-194`,
/// spec §3.5; parity quirk, keep verbatim).
pub const ERROR_CALLING_GEMINI_API: &str = "Error calling Gemini API!";

/// Parse failure when the payload carries no answer (both clients).
pub const NO_RESPONSE_FOUND: &str = "No response found! Problems at parsing!";

/// A failed `AskSmartAssistant` call: the C++ interface returns the
/// human-readable failure text in place of the answer together with
/// `isSuccess = false`; this carries that text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssistantError {
    /// Verbatim failure text (shown to the user by the callers).
    pub message: String,
}

impl AssistantError {
    /// Wraps a failure text.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for AssistantError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AssistantError {}

/// `AskSmartAssistant(prompt, displayPrompt)` as a callback, so callers
/// can route through an [`AssistantRegistry`], a bare
/// [`SmartAssistantProvider`] or a background worker.
pub type AskFn<'a> = &'a mut dyn FnMut(&str, &str) -> Result<String, AssistantError>;

/// C++ `SmartAssistantRegisterInterface` (spec §8
/// `SmartAssistantProvider`).
pub trait SmartAssistantProvider: Send + Sync {
    /// `GetSmartAssistantName()` — also the `[SmartAssistants]` INI key
    /// that holds this assistant's token.
    fn name(&self) -> &str;

    /// `GetSmartAssistantDescription()`.
    fn description(&self) -> &str;

    /// `ReceiveConfigToken(configData)`.
    fn receive_config_token(&mut self, token: &str);

    /// `GetCharacterLimit()`; both C++ assistants return
    /// [`CHARACTER_LIMIT`].
    fn character_limit(&self) -> u32 {
        CHARACTER_LIMIT
    }

    /// `AskSmartAssistant(prompt, displayPrompt, isSuccess)`.
    ///
    /// `display_prompt` is what the UI shows for the query; only
    /// `prompt` reaches the model.
    ///
    /// # Errors
    ///
    /// The verbatim C++ failure text when the transport or the
    /// response parser fails.
    fn ask(&self, prompt: &str, display_prompt: &str) -> Result<String, AssistantError>;
}

/// Failures of [`AssistantRegistry::register`] and
/// [`AssistantRegistry::select`] (C++ `MessageBox` texts).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// `RegisterSmartAssistantInterface`: empty name.
    EmptyName,
    /// `RegisterSmartAssistantInterface`: name already registered.
    DuplicateName(String),
    /// `GetSmartAssistantInterface`: nothing registered.
    NoAssistants,
    /// `GetSmartAssistantInterface`: assistants exist but none has a
    /// token.
    NotConfigured,
    /// Several assistants are configured and none is preferred yet:
    /// the caller must show the "Pick preferred Smart Assistant"
    /// dialog and call [`AssistantRegistry::set_preferred`].
    NeedsPick,
    /// The chosen index is out of range or not configured
    /// (`"Failed to pick a Smart Assistant!"`).
    InvalidIndex(usize),
}

impl core::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyName => f.write_str("Assistant has empty name!"),
            Self::DuplicateName(name) => {
                write!(f, "Assistant with name: \"{name}\" already exists!")
            }
            Self::NoAssistants => f.write_str("No SmartAssistants available!"),
            Self::NotConfigured => f.write_str(
                "Please configure the SmartAssistants in the vertical Panel for SmartAssistants before using them!",
            ),
            Self::NeedsPick => f.write_str("Pick preferred Smart Assistant"),
            Self::InvalidIndex(_) => f.write_str("Failed to pick a Smart Assistant!"),
        }
    }
}

impl std::error::Error for RegistryError {}

/// C++ `SmartAssistantPromptInterfaceProxy` (`QueryInterface.cpp`).
#[derive(Default)]
pub struct AssistantRegistry {
    assistants: Vec<Box<dyn SmartAssistantProvider>>,
    configured: Vec<bool>,
    prompt_retries: u32,
    preferred: Option<usize>,
    preferred_chat: Option<usize>,
}

impl AssistantRegistry {
    /// Empty registry (`promptRetriesCount` becomes meaningful after
    /// [`Self::start`]).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `RegisterSmartAssistantInterface`.
    ///
    /// # Errors
    ///
    /// [`RegistryError::EmptyName`] / [`RegistryError::DuplicateName`]
    /// exactly as the C++ checks (case-sensitive name comparison).
    pub fn register(&mut self, assistant: Box<dyn SmartAssistantProvider>) -> Result<(), RegistryError> {
        let name = assistant.name();
        if name.is_empty() {
            return Err(RegistryError::EmptyName);
        }
        if self.assistants.iter().any(|a| a.name() == name) {
            return Err(RegistryError::DuplicateName(name.to_owned()));
        }
        self.assistants.push(assistant);
        self.configured.push(false);
        Ok(())
    }

    /// `Start`: applies the `[SmartAssistants]` section. Returns one
    /// flag per registered assistant telling whether it received a
    /// non-empty token (the UI disables the prompt of the others with
    /// `MarkNoConfig`).
    ///
    /// C++ parity: with no assistants `promptRetriesCount` is `0`,
    /// otherwise `1` unless the section overrides it. An empty token
    /// value counts as *not configured* (C++ additionally skips the
    /// tab bookkeeping for that entry — a UI slot bug not replicated).
    pub fn start(&mut self, config: &AssistantConfig) -> Vec<bool> {
        if self.assistants.is_empty() {
            self.prompt_retries = 0;
            return Vec::new();
        }
        self.prompt_retries = config.prompt_retries.unwrap_or(1);
        for (assistant, flag) in self.assistants.iter_mut().zip(self.configured.iter_mut()) {
            let token = config.token(assistant.name()).filter(|t| !t.is_empty());
            *flag = token.is_some_and(|t| {
                assistant.receive_config_token(t);
                true
            });
        }
        self.configured.clone()
    }

    /// `GetPromptRetriesCount()`.
    #[must_use]
    pub const fn prompt_retries(&self) -> u32 {
        self.prompt_retries
    }

    /// Number of registered assistants.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.assistants.len()
    }

    /// Whether nothing is registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.assistants.is_empty()
    }

    /// Registered assistant by index.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&dyn SmartAssistantProvider> {
        self.assistants.get(index).map(AsRef::as_ref)
    }

    /// Whether the assistant at `index` received a token.
    #[must_use]
    pub fn is_configured(&self, index: usize) -> bool {
        self.configured.get(index).copied().unwrap_or(false)
    }

    /// C++ `validAssistants`.
    #[must_use]
    pub fn configured_count(&self) -> usize {
        self.configured.iter().filter(|&&c| c).count()
    }

    /// Currently preferred assistant (`prefferedIndex`).
    #[must_use]
    pub const fn preferred(&self) -> Option<usize> {
        self.preferred
    }

    /// Result of the "Pick preferred Smart Assistant" dialog.
    ///
    /// # Errors
    ///
    /// [`RegistryError::InvalidIndex`] when `index` is out of range or
    /// the assistant has no token.
    pub fn set_preferred(&mut self, index: usize) -> Result<(), RegistryError> {
        if self.is_configured(index) {
            self.preferred = Some(index);
            Ok(())
        } else {
            Err(RegistryError::InvalidIndex(index))
        }
    }

    /// `prefferedChatIndex`: the Smart Assistants tab forces the next
    /// [`Self::ask`] onto its own assistant (consumed by that call).
    pub const fn set_preferred_chat(&mut self, index: usize) {
        self.preferred_chat = Some(index);
    }

    /// `GetSmartAssistantInterface`: resolves which assistant answers
    /// non-tab queries (disassembly, HDF).
    ///
    /// # Errors
    ///
    /// [`RegistryError::NoAssistants`], [`RegistryError::NotConfigured`]
    /// (the two C++ message boxes) or [`RegistryError::NeedsPick`] when
    /// the caller must run the picker dialog first.
    pub fn select(&mut self) -> Result<usize, RegistryError> {
        match self.configured_count() {
            0 => Err(if self.assistants.is_empty() {
                RegistryError::NoAssistants
            } else {
                RegistryError::NotConfigured
            }),
            1 => {
                if self.preferred.is_none() {
                    self.preferred = self.configured.iter().position(|&c| c);
                }
                self.preferred.ok_or(RegistryError::NotConfigured)
            }
            _ => self.preferred.ok_or(RegistryError::NeedsPick),
        }
    }

    /// `SmartAssistantPromptInterfaceProxy::AskSmartAssistant`: routes
    /// to the tab's assistant when one was forced, else to the
    /// preferred one, and drops a single trailing `'\n'` from the
    /// answer (C++ `pop_back`, applied to failure texts as well).
    ///
    /// # Errors
    ///
    /// The assistant's failure text, or [`RegistryError::NoAssistants`]
    /// wording when no assistant can be resolved (C++ `assert`s).
    pub fn ask(&mut self, prompt: &str, display_prompt: &str) -> Result<String, AssistantError> {
        let index = self.preferred_chat.take().or(self.preferred);
        let Some(assistant) = index.and_then(|i| self.assistants.get(i)) else {
            return Err(AssistantError::new(RegistryError::NoAssistants.to_string()));
        };
        match assistant.ask(prompt, display_prompt) {
            Ok(mut answer) => {
                strip_one_trailing_newline(&mut answer);
                Ok(answer)
            }
            Err(mut err) => {
                strip_one_trailing_newline(&mut err.message);
                Err(err)
            }
        }
    }
}

fn strip_one_trailing_newline(text: &mut String) {
    if text.ends_with('\n') {
        text.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        name: &'static str,
        token: String,
        answer: Result<String, AssistantError>,
    }

    impl Fake {
        fn boxed(name: &'static str, answer: Result<String, AssistantError>) -> Box<dyn SmartAssistantProvider> {
            Box::new(Self {
                name,
                token: String::new(),
                answer,
            })
        }
    }

    impl SmartAssistantProvider for Fake {
        fn name(&self) -> &str {
            self.name
        }
        #[allow(clippy::unnecessary_literal_bound)]
        fn description(&self) -> &str {
            "fake"
        }
        fn receive_config_token(&mut self, token: &str) {
            self.token = token.to_owned();
        }
        fn ask(&self, _prompt: &str, _display: &str) -> Result<String, AssistantError> {
            assert!(!self.token.is_empty(), "token must be distributed before use");
            self.answer.clone()
        }
    }

    fn two_assistants() -> AssistantRegistry {
        let mut reg = AssistantRegistry::new();
        reg.register(Fake::boxed("GeminiPro1.5", Ok("gemini\n".into())))
            .expect("register");
        reg.register(Fake::boxed("GPT4o", Ok("gpt\n\n".into()))).expect("register");
        reg
    }

    #[test]
    fn register_rejects_empty_and_duplicate_names() {
        let mut reg = AssistantRegistry::new();
        assert_eq!(reg.register(Fake::boxed("", Ok(String::new()))), Err(RegistryError::EmptyName));
        reg.register(Fake::boxed("GPT4o", Ok(String::new()))).expect("first");
        let err = reg.register(Fake::boxed("GPT4o", Ok(String::new()))).expect_err("dup");
        assert_eq!(err, RegistryError::DuplicateName("GPT4o".into()));
        assert_eq!(err.to_string(), "Assistant with name: \"GPT4o\" already exists!");
        assert_eq!(RegistryError::EmptyName.to_string(), "Assistant has empty name!");
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.get(0).map(SmartAssistantProvider::name), Some("GPT4o"));
        assert!(reg.get(1).is_none());
    }

    #[test]
    fn start_distributes_tokens_and_retries() {
        let mut reg = two_assistants();
        let cfg = AssistantConfig::from_ini_str("[SmartAssistants]\nGPT4o = sk-abc\nGeminiPro1.5 =\nPromptRetries = 3\n");
        assert_eq!(reg.start(&cfg), vec![false, true]);
        assert_eq!(reg.prompt_retries(), 3);
        assert_eq!(reg.configured_count(), 1);
        assert!(!reg.is_configured(0));
        assert!(reg.is_configured(1));
        assert!(!reg.is_configured(7));
    }

    #[test]
    fn start_defaults_retries_one_and_zero_without_assistants() {
        let mut reg = two_assistants();
        reg.start(&AssistantConfig::from_ini_str(""));
        assert_eq!(reg.prompt_retries(), 1);
        let mut empty = AssistantRegistry::new();
        assert!(empty
            .start(&AssistantConfig::from_ini_str("[SmartAssistants]\nPromptRetries=5\n"))
            .is_empty());
        assert_eq!(empty.prompt_retries(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn select_state_machine() {
        let mut empty = AssistantRegistry::new();
        assert_eq!(empty.select(), Err(RegistryError::NoAssistants));

        let mut reg = two_assistants();
        assert_eq!(reg.select(), Err(RegistryError::NotConfigured));

        reg.start(&AssistantConfig::from_ini_str("[SmartAssistants]\nGPT4o = k\n"));
        assert_eq!(reg.select(), Ok(1));
        assert_eq!(reg.preferred(), Some(1));

        let mut both = two_assistants();
        both.start(&AssistantConfig::from_ini_str("[SmartAssistants]\nGPT4o = k\nGeminiPro1.5 = g\n"));
        assert_eq!(both.select(), Err(RegistryError::NeedsPick));
        assert_eq!(both.set_preferred(5), Err(RegistryError::InvalidIndex(5)));
        both.set_preferred(0).expect("pick");
        assert_eq!(both.select(), Ok(0));
    }

    #[test]
    fn ask_routes_and_strips_one_newline() {
        let mut reg = two_assistants();
        reg.start(&AssistantConfig::from_ini_str("[SmartAssistants]\nGPT4o = k\nGeminiPro1.5 = g\n"));
        assert!(reg.ask("p", "d").is_err(), "nothing preferred yet");
        reg.set_preferred(0).expect("pick");
        assert_eq!(reg.ask("p", "d"), Ok("gemini".into()));
        reg.set_preferred_chat(1);
        assert_eq!(reg.ask("p", "d"), Ok("gpt\n".into()));
        // The chat override is consumed by one call.
        assert_eq!(reg.ask("p", "d"), Ok("gemini".into()));
    }

    #[test]
    fn ask_error_text_also_loses_trailing_newline() {
        let mut reg = AssistantRegistry::new();
        reg.register(Fake::boxed("X", Err(AssistantError::new("boom\n"))))
            .expect("register");
        reg.start(&AssistantConfig::from_ini_str("[SmartAssistants]\nX = t\n"));
        assert_eq!(reg.select(), Ok(0));
        assert_eq!(reg.ask("p", "d"), Err(AssistantError::new("boom")));
        assert_eq!(AssistantError::new("m").to_string(), "m");
    }

    #[test]
    fn default_character_limit_is_1024() {
        let f = Fake {
            name: "n",
            token: String::new(),
            answer: Ok(String::new()),
        };
        assert_eq!(f.character_limit(), 1024);
        assert_eq!(f.description(), "fake");
    }
}
