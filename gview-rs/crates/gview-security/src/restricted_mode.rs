//! `RestrictedMode`: signed feature-restriction policies
//! (spec `04_SERVICES` §7.1–7.3; C++ `Security/RestrictedMode.cpp`).
//!
//! A policy is a JSON document plus a detached 64-byte Ed25519
//! signature, verified against a 32-byte raw public key **before**
//! anything is parsed (fail closed, spec §9.5). Loading
//! ([`load_policy_from_files`] / [`load_policy_from_bytes`]) performs
//! the C++ `LoadPolicyFromFiles` steps in order:
//!
//! 1. public key must be 32 bytes;
//! 2. read the JSON file and the signature file (each non-empty and at
//!    most [`MAX_POLICY_FILE_SIZE`] bytes);
//! 3. signature must be 64 bytes and verify over the raw JSON bytes;
//! 4. parse the JSON (`disabledFeatures` is a **string array** —
//!    `"Copy"`, `"Export"`, … — unknown names are ignored; any present
//!    key of the wrong type is a parse error, as nlohmann throws);
//! 5. validate the `startsAt` / `endsAt` epoch-seconds window.
//!
//! [`RestrictedMode`] is the activation state (C++ `Internal::Activate`
//! / `Deactivate` / `IsFeatureDisabled` / `IsPluginAllowed` /
//! `GetWatermark`), also available as a process-wide instance through
//! [`global`]. Deactivation securely erases the stored policy
//! (`zeroize`). The C++ `VirtualLock`/`mlock` page pinning and the
//! Win32 keyboard hook / `SetWindowDisplayAffinity` are OS calls that
//! need `unsafe` FFI and are out of scope for this `forbid(unsafe_code)`
//! crate; [`RestrictedMode::screen_protection_requested`] reports
//! whether a shell with such capabilities should engage them.
//!
//! `LLMHints` gating (C++ `SummaryController::RequestSummary`): while
//! active with `LLMHints` disabled, [`RestrictedMode::llm_hints_allowed`]
//! is `false` and the assistant summary must return empty.

use std::path::Path;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use zeroize::Zeroize;

/// Raw Ed25519 public key length.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIGNATURE_SIZE: usize = 64;
/// Largest policy / signature file accepted (C++ `ReadFileToVector`:
/// `size > 10 * 1024 * 1024` is rejected).
pub const MAX_POLICY_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// C++ `RestrictedMode::Feature` (bit flags).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Feature {
    /// Copy to clipboard from viewers.
    Copy = 1 << 0,
    /// Export / save data.
    Export = 1 << 1,
    /// Save-as.
    SaveAs = 1 << 2,
    /// Plugin loading (subject to `allowedPlugins`).
    Plugins = 1 << 3,
    /// LLM / `SmartAssistant` hints and summaries.
    LlmHints = 1 << 4,
    /// Clipboard access.
    Clipboard = 1 << 5,
    /// Screenshots / screen capture.
    Screenshots = 1 << 6,
}

impl Feature {
    /// All features, in bit order.
    pub const ALL: [Self; 7] = [
        Self::Copy,
        Self::Export,
        Self::SaveAs,
        Self::Plugins,
        Self::LlmHints,
        Self::Clipboard,
        Self::Screenshots,
    ];

    /// The JSON name (`ParsePolicyJson` string comparisons).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Copy => "Copy",
            Self::Export => "Export",
            Self::SaveAs => "SaveAs",
            Self::Plugins => "Plugins",
            Self::LlmHints => "LLMHints",
            Self::Clipboard => "Clipboard",
            Self::Screenshots => "Screenshots",
        }
    }

    /// Parses a JSON feature name (exact, case-sensitive match like the
    /// C++ `==` chain); unknown names yield `None` and are skipped.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.name() == name)
    }

    /// Bit value (`uint32` enum value).
    #[must_use]
    pub const fn bits(self) -> u32 {
        self as u32
    }
}

/// C++ `RestrictedMode::Policy`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// `id`.
    pub id: String,
    /// `purpose`.
    pub purpose: String,
    /// `startsAt` — seconds since the epoch (0 = unbounded).
    pub starts_at: u64,
    /// `endsAt` — seconds since the epoch (0 = unbounded).
    pub ends_at: u64,
    /// `disabledFeatures`, in document order.
    pub disabled_features: Vec<Feature>,
    /// `allowedPlugins` — allow-list consulted only when
    /// [`Feature::Plugins`] is disabled.
    pub allowed_plugins: Vec<String>,
    /// `watermark`.
    pub watermark: String,
    /// `bestEffortScreenProtect` (default `true`).
    pub best_effort_screen_protect: bool,
    /// `contentKeyId` — decoded from a hex string.
    pub content_key_id: Vec<u8>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            id: String::new(),
            purpose: String::new(),
            starts_at: 0,
            ends_at: 0,
            disabled_features: Vec::new(),
            allowed_plugins: Vec::new(),
            watermark: String::new(),
            best_effort_screen_protect: true,
            content_key_id: Vec::new(),
        }
    }
}

impl Policy {
    /// Linear scan of `disabledFeatures` (C++ `IsFeatureDisabled`).
    #[must_use]
    pub fn is_feature_disabled(&self, feature: Feature) -> bool {
        self.disabled_features.contains(&feature)
    }

    /// Secure erase (C++ `ProtectedPolicyStorage::Clear`): every
    /// buffer is zeroized before the policy returns to its default.
    pub fn secure_clear(&mut self) {
        self.id.zeroize();
        self.purpose.zeroize();
        self.starts_at.zeroize();
        self.ends_at.zeroize();
        self.disabled_features.clear();
        for plugin in &mut self.allowed_plugins {
            plugin.zeroize();
        }
        self.allowed_plugins.clear();
        self.watermark.zeroize();
        self.content_key_id.zeroize();
        *self = Self::default();
    }
}

impl Drop for Policy {
    fn drop(&mut self) {
        self.id.zeroize();
        self.purpose.zeroize();
        self.watermark.zeroize();
        self.content_key_id.zeroize();
        for plugin in &mut self.allowed_plugins {
            plugin.zeroize();
        }
    }
}

/// Policy loading / activation failures. `Display` reproduces the
/// C++ `GStatus::Error` messages.
#[derive(Debug)]
pub enum PolicyError {
    /// Public key is not 32 bytes.
    InvalidPublicKeySize {
        /// Provided length.
        size: usize,
    },
    /// The JSON file could not be read (missing, empty, too large).
    ReadJson(std::io::Error),
    /// The signature file could not be read (missing, empty, too large).
    ReadSignature(std::io::Error),
    /// Signature is not 64 bytes.
    InvalidSignatureSize {
        /// Provided length.
        size: usize,
    },
    /// Ed25519 verification failed (or the key is not a valid point).
    SignatureVerificationFailed,
    /// Malformed JSON.
    JsonParse(String),
    /// Well-formed JSON with wrong types / bad hex.
    PolicyParse(String),
    /// `now < startsAt`.
    NotYetActive,
    /// `now > endsAt`.
    Expired,
    /// `Activate` while already active.
    AlreadyActive,
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPublicKeySize { .. } => {
                write!(f, "Invalid public key size (expected 32 bytes for Ed25519)")
            }
            Self::ReadJson(_) => write!(f, "Failed to read policy JSON file"),
            Self::ReadSignature(_) => write!(f, "Failed to read signature file"),
            Self::InvalidSignatureSize { .. } => {
                write!(f, "Invalid signature size (expected 64 bytes for Ed25519)")
            }
            Self::SignatureVerificationFailed => write!(f, "Policy signature verification failed"),
            Self::JsonParse(msg) => write!(f, "JSON parse error: {msg}"),
            Self::PolicyParse(msg) => write!(f, "Policy parse error: {msg}"),
            Self::NotYetActive => write!(f, "Policy not yet active (starts in the future)"),
            Self::Expired => write!(f, "Policy has expired"),
            Self::AlreadyActive => write!(f, "Restricted mode already active"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Seconds since the Unix epoch (C++ `system_clock::now()` cast).
#[must_use]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// C++ `VerifyEd25519Signature`: `false` for wrong sizes, an invalid
/// key encoding, or a bad signature. Never panics.
#[must_use]
pub fn verify_ed25519(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let Ok(key_bytes) = <[u8; ED25519_PUBLIC_KEY_SIZE]>::try_from(public_key) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; ED25519_SIGNATURE_SIZE]>::try_from(signature) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify(message, &signature).is_ok()
}

/// `j.value(key, default)` for strings: missing → default, present
/// non-string → type error (nlohmann throws `type_error`).
fn json_string(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<String, PolicyError> {
    match obj.get(key) {
        None => Ok(String::new()),
        Some(serde_json::Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(PolicyError::JsonParse(format!(
            "type must be string, but is {}",
            json_type_name(other)
        ))),
    }
}

/// `j.value(key, 0ULL)`: missing → 0, present non-integer → type error.
fn json_u64(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<u64, PolicyError> {
    match obj.get(key) {
        None => Ok(0),
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .or_else(|| n.as_i64().map(i64::cast_unsigned))
            .ok_or_else(|| PolicyError::JsonParse(String::from("type must be number, but is float"))),
        Some(other) => Err(PolicyError::JsonParse(format!(
            "type must be number, but is {}",
            json_type_name(other)
        ))),
    }
}

/// `j.value(key, true)`: missing → `true`, present non-bool → type error.
fn json_bool(obj: &serde_json::Map<String, serde_json::Value>, key: &str, default: bool) -> Result<bool, PolicyError> {
    match obj.get(key) {
        None => Ok(default),
        Some(serde_json::Value::Bool(b)) => Ok(*b),
        Some(other) => Err(PolicyError::JsonParse(format!(
            "type must be boolean, but is {}",
            json_type_name(other)
        ))),
    }
}

const fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// C++ `contentKeyId` hex decoding: pairs of characters through
/// `std::stoul(pair, nullptr, 16)` — a pair with no leading hex digit
/// throws (`invalid_argument` → "Policy parse error"), a pair whose
/// second character is not hex parses its first digit only; a
/// trailing odd character is ignored (`i + 1 < size`).
fn parse_content_key_id(hex: &str) -> Result<Vec<u8>, PolicyError> {
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0_usize;
    while i.saturating_add(1) < bytes.len() {
        let first = bytes.get(i).copied().unwrap_or(0);
        let second = bytes.get(i.saturating_add(1)).copied().unwrap_or(0);
        let hi = (first as char)
            .to_digit(16)
            .ok_or_else(|| PolicyError::PolicyParse(String::from("stoul")))?;
        let value = (second as char)
            .to_digit(16)
            .map_or(hi, |lo| (hi << 4) | lo);
        out.push(value as u8);
        i = i.saturating_add(2);
    }
    Ok(out)
}

/// C++ `ParsePolicyJson`.
///
/// # Errors
///
/// [`PolicyError::JsonParse`] for malformed JSON or a present key of
/// the wrong type; [`PolicyError::PolicyParse`] for a bad
/// `contentKeyId` hex pair.
pub fn parse_policy_json(json: &[u8]) -> Result<Policy, PolicyError> {
    let value: serde_json::Value =
        serde_json::from_slice(json).map_err(|e| PolicyError::JsonParse(e.to_string()))?;
    let Some(obj) = value.as_object() else {
        return Err(PolicyError::JsonParse(format!(
            "cannot use value() with {}",
            json_type_name(&value)
        )));
    };

    let mut policy = Policy::default();
    policy.id = json_string(obj, "id")?;
    policy.purpose = json_string(obj, "purpose")?;
    policy.starts_at = json_u64(obj, "startsAt")?;
    policy.ends_at = json_u64(obj, "endsAt")?;
    policy.watermark = json_string(obj, "watermark")?;
    policy.best_effort_screen_protect = json_bool(obj, "bestEffortScreenProtect", true)?;

    if let Some(serde_json::Value::Array(items)) = obj.get("disabledFeatures") {
        for item in items {
            let Some(name) = item.as_str() else {
                return Err(PolicyError::JsonParse(format!(
                    "type must be string, but is {}",
                    json_type_name(item)
                )));
            };
            if let Some(feature) = Feature::from_name(name) {
                policy.disabled_features.push(feature);
            }
        }
    }

    if let Some(serde_json::Value::Array(items)) = obj.get("allowedPlugins") {
        for item in items {
            let Some(name) = item.as_str() else {
                return Err(PolicyError::JsonParse(format!(
                    "type must be string, but is {}",
                    json_type_name(item)
                )));
            };
            policy.allowed_plugins.push(name.to_owned());
        }
    }

    if let Some(serde_json::Value::String(hex)) = obj.get("contentKeyId") {
        policy.content_key_id = parse_content_key_id(hex)?;
    }

    Ok(policy)
}

/// C++ `ValidatePolicyTimeWindow` against `now` (epoch seconds).
///
/// # Errors
///
/// [`PolicyError::NotYetActive`] when `startsAt > 0 && now < startsAt`,
/// [`PolicyError::Expired`] when `endsAt > 0 && now > endsAt`.
pub const fn validate_time_window(policy: &Policy, now: u64) -> Result<(), PolicyError> {
    if policy.starts_at > 0 && now < policy.starts_at {
        return Err(PolicyError::NotYetActive);
    }
    if policy.ends_at > 0 && now > policy.ends_at {
        return Err(PolicyError::Expired);
    }
    Ok(())
}

/// C++ `LoadPolicyFromFiles` on in-memory contents: key size →
/// signature size → verify → parse → time window, at `now`.
///
/// # Errors
///
/// Any [`PolicyError`] except the I/O ones.
pub fn load_policy_from_bytes(
    json: &[u8],
    signature: &[u8],
    public_key: &[u8],
    now: u64,
) -> Result<Policy, PolicyError> {
    if public_key.len() != ED25519_PUBLIC_KEY_SIZE {
        return Err(PolicyError::InvalidPublicKeySize {
            size: public_key.len(),
        });
    }
    if signature.len() != ED25519_SIGNATURE_SIZE {
        return Err(PolicyError::InvalidSignatureSize {
            size: signature.len(),
        });
    }
    if !verify_ed25519(json, signature, public_key) {
        return Err(PolicyError::SignatureVerificationFailed);
    }
    let policy = parse_policy_json(json)?;
    validate_time_window(&policy, now)?;
    Ok(policy)
}

/// C++ `ReadFileToVector`: rejects empty files and files above
/// [`MAX_POLICY_FILE_SIZE`] before reading.
fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    let len = std::fs::metadata(path)?.len();
    if len == 0 || len > MAX_POLICY_FILE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("policy file size {len} outside 1..={MAX_POLICY_FILE_SIZE}"),
        ));
    }
    std::fs::read(path)
}

/// C++ `LoadPolicyFromFiles(jsonPath, signaturePath, publicKey, out)`
/// evaluated at the current time.
///
/// # Errors
///
/// [`PolicyError::ReadJson`] / [`PolicyError::ReadSignature`] for
/// unreadable, empty or oversized files, otherwise as
/// [`load_policy_from_bytes`].
pub fn load_policy_from_files(json_path: &Path, signature_path: &Path, public_key: &[u8]) -> Result<Policy, PolicyError> {
    if public_key.len() != ED25519_PUBLIC_KEY_SIZE {
        return Err(PolicyError::InvalidPublicKeySize {
            size: public_key.len(),
        });
    }
    let json = read_bounded(json_path).map_err(PolicyError::ReadJson)?;
    let signature = read_bounded(signature_path).map_err(PolicyError::ReadSignature)?;
    load_policy_from_bytes(&json, &signature, public_key, now_secs())
}

/// Activation state (C++ `g_policyStorage` + `g_isActive`).
#[derive(Debug, Default)]
pub struct RestrictedMode {
    state: Mutex<Option<Policy>>,
}

impl RestrictedMode {
    /// An inactive instance.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Policy>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// C++ `Internal::Activate`: rejects double activation, re-checks
    /// the time window at `now`, then stores the policy.
    ///
    /// # Errors
    ///
    /// [`PolicyError::AlreadyActive`], [`PolicyError::NotYetActive`],
    /// [`PolicyError::Expired`].
    pub fn activate(&self, policy: Policy, now: u64) -> Result<(), PolicyError> {
        validate_time_window(&policy, now)?;
        let mut state = self.lock();
        if state.is_some() {
            return Err(PolicyError::AlreadyActive);
        }
        *state = Some(policy);
        drop(state);
        Ok(())
    }

    /// C++ `Internal::Deactivate`: securely erases the stored policy;
    /// a no-op when inactive.
    pub fn deactivate(&self) {
        let mut state = self.lock();
        if let Some(policy) = state.as_mut() {
            policy.secure_clear();
        }
        *state = None;
    }

    /// C++ `IsActive`.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.lock().is_some()
    }

    /// C++ `GetCurrentPolicy`: a copy of the active policy, `None`
    /// when inactive.
    #[must_use]
    pub fn current_policy(&self) -> Option<Policy> {
        self.lock().clone()
    }

    /// C++ `Internal::IsFeatureDisabled`: `false` when inactive.
    #[must_use]
    pub fn is_feature_disabled(&self, feature: Feature) -> bool {
        self.lock()
            .as_ref()
            .is_some_and(|p| p.is_feature_disabled(feature))
    }

    /// C++ `Internal::IsPluginAllowed`: everything is allowed when
    /// inactive or when `Plugins` is not disabled; otherwise only the
    /// `allowedPlugins` allow-list (exact match).
    #[must_use]
    pub fn is_plugin_allowed(&self, plugin_name: &str) -> bool {
        self.lock().as_ref().is_none_or(|policy| {
            !policy.is_feature_disabled(Feature::Plugins)
                || policy.allowed_plugins.iter().any(|allowed| allowed == plugin_name)
        })
    }

    /// C++ `Internal::GetWatermark`: empty when inactive.
    #[must_use]
    pub fn watermark(&self) -> String {
        self.lock().as_ref().map(|p| p.watermark.clone()).unwrap_or_default()
    }

    /// C++ `Activate` screen-protection decision: `Screenshots` is
    /// disabled **and** `bestEffortScreenProtect` is set. The shell
    /// engages the platform hooks when this is `true`.
    #[must_use]
    pub fn screen_protection_requested(&self) -> bool {
        self.lock().as_ref().is_some_and(|p| {
            p.is_feature_disabled(Feature::Screenshots) && p.best_effort_screen_protect
        })
    }

    /// The `SummaryController::RequestSummary` gate: LLM hints are
    /// allowed unless the mode is active with `LLMHints` disabled.
    #[must_use]
    pub fn llm_hints_allowed(&self) -> bool {
        !self.is_feature_disabled(Feature::LlmHints)
    }
}

/// The process-wide instance (C++ file-scope globals).
#[must_use]
pub fn global() -> &'static RestrictedMode {
    static GLOBAL: OnceLock<RestrictedMode> = OnceLock::new();
    GLOBAL.get_or_init(RestrictedMode::new)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const SEED: [u8; 32] = [7; 32];
    const NOW: u64 = 1_700_000_000;

    fn keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&SEED);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn sign(json: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let (sk, pk) = keypair();
        (sk.sign(json).to_bytes().to_vec(), pk)
    }

    const FULL_POLICY: &str = r#"{
        "id": "policy-1",
        "purpose": "exam",
        "startsAt": 1600000000,
        "endsAt": 1800000000,
        "disabledFeatures": ["Copy", "LLMHints", "Plugins", "Bogus", "Screenshots"],
        "allowedPlugins": ["PE", "ELF"],
        "watermark": "CONFIDENTIAL",
        "bestEffortScreenProtect": false,
        "contentKeyId": "deadBEEF"
    }"#;

    #[test]
    fn full_policy_roundtrip_through_signature_and_parse() {
        let (sig, pk) = sign(FULL_POLICY.as_bytes());
        let policy = load_policy_from_bytes(FULL_POLICY.as_bytes(), &sig, &pk, NOW).expect("load");
        assert_eq!(policy.id, "policy-1");
        assert_eq!(policy.purpose, "exam");
        assert_eq!(policy.starts_at, 1_600_000_000);
        assert_eq!(policy.ends_at, 1_800_000_000);
        assert_eq!(
            policy.disabled_features,
            [Feature::Copy, Feature::LlmHints, Feature::Plugins, Feature::Screenshots]
        );
        assert_eq!(policy.allowed_plugins, ["PE", "ELF"]);
        assert_eq!(policy.watermark, "CONFIDENTIAL");
        assert!(!policy.best_effort_screen_protect);
        assert_eq!(policy.content_key_id, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn tampered_json_is_rejected_before_parsing() {
        let (sig, pk) = sign(FULL_POLICY.as_bytes());
        let tampered = FULL_POLICY.replace("\"Copy\"", "\"Export\"");
        assert!(matches!(
            load_policy_from_bytes(tampered.as_bytes(), &sig, &pk, NOW),
            Err(PolicyError::SignatureVerificationFailed)
        ));
        // Even syntactically broken JSON fails on the signature first.
        assert!(matches!(
            load_policy_from_bytes(b"{ not json", &sig, &pk, NOW),
            Err(PolicyError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn wrong_key_flipped_signature_and_bad_sizes_fail_closed() {
        let (sig, pk) = sign(FULL_POLICY.as_bytes());
        let mut other_pk = pk;
        other_pk[0] ^= 0x01;
        assert!(matches!(
            load_policy_from_bytes(FULL_POLICY.as_bytes(), &sig, &other_pk, NOW),
            Err(PolicyError::SignatureVerificationFailed)
        ));
        let mut bad_sig = sig.clone();
        bad_sig[10] ^= 0x80;
        assert!(matches!(
            load_policy_from_bytes(FULL_POLICY.as_bytes(), &bad_sig, &pk, NOW),
            Err(PolicyError::SignatureVerificationFailed)
        ));
        assert!(matches!(
            load_policy_from_bytes(FULL_POLICY.as_bytes(), &sig[..63], &pk, NOW),
            Err(PolicyError::InvalidSignatureSize { size: 63 })
        ));
        assert!(matches!(
            load_policy_from_bytes(FULL_POLICY.as_bytes(), &sig, &pk[..31], NOW),
            Err(PolicyError::InvalidPublicKeySize { size: 31 })
        ));
        assert!(!verify_ed25519(b"m", &[0; 64], &[0xFF; 32]));
        assert!(!verify_ed25519(b"m", &[0; 10], &pk));
    }

    #[test]
    fn time_window_is_enforced() {
        let (sig, pk) = sign(FULL_POLICY.as_bytes());
        assert!(matches!(
            load_policy_from_bytes(FULL_POLICY.as_bytes(), &sig, &pk, 1_500_000_000),
            Err(PolicyError::NotYetActive)
        ));
        assert!(matches!(
            load_policy_from_bytes(FULL_POLICY.as_bytes(), &sig, &pk, 1_900_000_000),
            Err(PolicyError::Expired)
        ));
        // Boundaries are inclusive; zero means unbounded.
        assert!(load_policy_from_bytes(FULL_POLICY.as_bytes(), &sig, &pk, 1_600_000_000).is_ok());
        assert!(load_policy_from_bytes(FULL_POLICY.as_bytes(), &sig, &pk, 1_800_000_000).is_ok());
        let open = Policy::default();
        assert!(validate_time_window(&open, 0).is_ok());
        assert!(validate_time_window(&open, u64::MAX).is_ok());
    }

    #[test]
    fn missing_keys_take_cpp_defaults() {
        let policy = parse_policy_json(b"{}").expect("parse");
        assert_eq!(policy, Policy::default());
        assert!(policy.best_effort_screen_protect);
        assert!(policy.disabled_features.is_empty());
    }

    #[test]
    fn wrong_types_are_parse_errors_like_nlohmann() {
        for bad in [
            r#"{"id": 5}"#,
            r#"{"startsAt": "soon"}"#,
            r#"{"bestEffortScreenProtect": "yes"}"#,
            r#"{"disabledFeatures": [1]}"#,
            r#"{"allowedPlugins": [null]}"#,
            "[]",
            "{",
        ] {
            assert!(
                matches!(parse_policy_json(bad.as_bytes()), Err(PolicyError::JsonParse(_))),
                "{bad}"
            );
        }
        // Non-array feature lists are ignored (C++ `is_array()` guard).
        let policy = parse_policy_json(br#"{"disabledFeatures": "Copy", "allowedPlugins": 3}"#).expect("parse");
        assert!(policy.disabled_features.is_empty());
        assert!(policy.allowed_plugins.is_empty());
    }

    #[test]
    fn feature_names_are_string_array_not_numeric_flags() {
        let policy = parse_policy_json(br#"{"disabledFeatures": ["Export", "SaveAs", "Clipboard", "copy"]}"#)
            .expect("parse");
        assert_eq!(
            policy.disabled_features,
            [Feature::Export, Feature::SaveAs, Feature::Clipboard]
        );
        for feature in Feature::ALL {
            assert_eq!(Feature::from_name(feature.name()), Some(feature));
        }
        assert_eq!(Feature::Copy.bits(), 1);
        assert_eq!(Feature::Screenshots.bits(), 64);
        assert_eq!(Feature::LlmHints.name(), "LLMHints");
    }

    #[test]
    fn content_key_id_hex_mirrors_stoul() {
        assert_eq!(parse_content_key_id("0aFf").expect("hex"), [0x0A, 0xFF]);
        // Odd trailing character ignored.
        assert_eq!(parse_content_key_id("abc").expect("hex"), [0xAB]);
        // Second char not hex: stoul parses the first digit only.
        assert_eq!(parse_content_key_id("1g").expect("hex"), [0x01]);
        // First char not hex: stoul throws.
        assert!(matches!(
            parse_content_key_id("g1"),
            Err(PolicyError::PolicyParse(_))
        ));
        assert!(parse_content_key_id("").expect("hex").is_empty());
        assert!(matches!(
            parse_policy_json(br#"{"contentKeyId": "zz"}"#),
            Err(PolicyError::PolicyParse(_))
        ));
    }

    fn active_mode() -> RestrictedMode {
        let mode = RestrictedMode::new();
        let policy = parse_policy_json(FULL_POLICY.as_bytes()).expect("parse");
        mode.activate(policy, NOW).expect("activate");
        mode
    }

    #[test]
    fn inactive_mode_allows_everything() {
        let mode = RestrictedMode::new();
        assert!(!mode.is_active());
        assert!(mode.current_policy().is_none());
        assert!(!mode.is_feature_disabled(Feature::Copy));
        assert!(mode.is_plugin_allowed("anything"));
        assert!(mode.watermark().is_empty());
        assert!(mode.llm_hints_allowed());
        assert!(!mode.screen_protection_requested());
        mode.deactivate(); // no-op
        assert!(!mode.is_active());
    }

    #[test]
    fn activation_gates_features_plugins_and_llm_hints() {
        let mode = active_mode();
        assert!(mode.is_active());
        assert!(mode.is_feature_disabled(Feature::Copy));
        assert!(mode.is_feature_disabled(Feature::LlmHints));
        assert!(!mode.is_feature_disabled(Feature::Export));
        assert!(!mode.llm_hints_allowed());
        assert!(mode.is_plugin_allowed("PE"));
        assert!(!mode.is_plugin_allowed("pe"));
        assert!(!mode.is_plugin_allowed("ZIP"));
        assert_eq!(mode.watermark(), "CONFIDENTIAL");
        // Screenshots disabled but bestEffortScreenProtect = false.
        assert!(!mode.screen_protection_requested());
        assert_eq!(mode.current_policy().map(|p| p.id.clone()), Some(String::from("policy-1")));
    }

    #[test]
    fn plugins_allowed_when_plugins_feature_not_disabled() {
        let mode = RestrictedMode::new();
        let policy = parse_policy_json(br#"{"disabledFeatures": ["Copy"], "allowedPlugins": ["PE"]}"#).expect("parse");
        mode.activate(policy, NOW).expect("activate");
        assert!(mode.is_plugin_allowed("ZIP"));
    }

    #[test]
    fn screen_protection_requested_with_best_effort_default() {
        let mode = RestrictedMode::new();
        let policy = parse_policy_json(br#"{"disabledFeatures": ["Screenshots"]}"#).expect("parse");
        mode.activate(policy, NOW).expect("activate");
        assert!(mode.screen_protection_requested());
    }

    #[test]
    fn double_activation_and_expired_activation_are_rejected() {
        let mode = active_mode();
        let again = parse_policy_json(FULL_POLICY.as_bytes()).expect("parse");
        assert!(matches!(mode.activate(again, NOW), Err(PolicyError::AlreadyActive)));
        assert!(mode.is_feature_disabled(Feature::Copy));

        let fresh = RestrictedMode::new();
        let expired = parse_policy_json(FULL_POLICY.as_bytes()).expect("parse");
        assert!(matches!(
            fresh.activate(expired, 1_900_000_000),
            Err(PolicyError::Expired)
        ));
        assert!(!fresh.is_active());
    }

    #[test]
    fn deactivate_clears_state_and_secure_clear_zeroes_policy() {
        let mode = active_mode();
        mode.deactivate();
        assert!(!mode.is_active());
        assert!(!mode.is_feature_disabled(Feature::Copy));
        assert!(mode.watermark().is_empty());

        let mut policy = parse_policy_json(FULL_POLICY.as_bytes()).expect("parse");
        policy.secure_clear();
        assert_eq!(policy, Policy::default());
    }

    #[test]
    fn global_instance_is_shared() {
        assert!(std::ptr::eq(global(), global()));
    }

    #[test]
    fn files_are_read_bounded_and_verified() {
        let dir = std::env::temp_dir().join(format!("gview-policy-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let json_path = dir.join("policy.json");
        let sig_path = dir.join("policy.sig");
        let (sig, pk) = sign(FULL_POLICY.as_bytes());
        std::fs::write(&json_path, FULL_POLICY).expect("write json");
        std::fs::write(&sig_path, &sig).expect("write sig");

        let policy = load_policy_from_files(&json_path, &sig_path, &pk).expect("load");
        assert_eq!(policy.id, "policy-1");

        assert!(matches!(
            load_policy_from_files(&dir.join("missing.json"), &sig_path, &pk),
            Err(PolicyError::ReadJson(_))
        ));
        let empty = dir.join("empty.sig");
        std::fs::write(&empty, b"").expect("write empty");
        assert!(matches!(
            load_policy_from_files(&json_path, &empty, &pk),
            Err(PolicyError::ReadSignature(_))
        ));
        assert!(matches!(
            load_policy_from_files(&json_path, &sig_path, &pk[..16]),
            Err(PolicyError::InvalidPublicKeySize { size: 16 })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn error_messages_match_cpp_gstatus_strings() {
        assert_eq!(
            PolicyError::InvalidPublicKeySize { size: 0 }.to_string(),
            "Invalid public key size (expected 32 bytes for Ed25519)"
        );
        assert_eq!(
            PolicyError::SignatureVerificationFailed.to_string(),
            "Policy signature verification failed"
        );
        assert_eq!(PolicyError::Expired.to_string(), "Policy has expired");
        assert_eq!(
            PolicyError::AlreadyActive.to_string(),
            "Restricted mode already active"
        );
    }
}
