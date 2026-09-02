//! `GView` security services (spec `04_SERVICES` §7).
//!
//! Port of `GViewCore/src/Security/`: [`restricted_mode`]
//! (`RestrictedMode.cpp` — Ed25519-signed policy files, feature
//! gating, plugin allow-list; fail closed) and [`crypto`]
//! (`CryptoGView.cpp` — AES-256-GCM, SHA-256, HKDF-SHA256, CSPRNG,
//! secure erase), and [`authenticode`] (`DigitalSignature/Authenticode.cpp`
//! — the PE Authenticode digest with the checksum / certificate-table
//! exclusions and the PKCS#7 `SpcIndirectDataContent` walk).

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod authenticode;
pub mod crypto;
pub mod restricted_mode;
