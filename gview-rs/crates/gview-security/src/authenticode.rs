//! Authenticode PE digest and signature parser.
//!
//! Spec `04_SERVICES` §5.2–§5.3; C++ `DigitalSignature/Authenticode.cpp`
//! `AuthenticodeParser::AuthenticodeParse`, `AuthenticodeDigest`,
//! `AuthenticodeParseSignature`, `ParseNestedAuthenticode`.
//!
//! The critical part is the file digest: the bytes that are hashed and
//! the two holes that are **excluded** must match `signtool` exactly
//! (`AuthenticodeDigest`, `Authenticode.cpp:503-611`):
//!
//! ```text
//! [0, pe + 0x58)                         DOS stub + PE header up to CheckSum
//! [pe + 0x58, pe + 0x5C)                 EXCLUDED — CheckSum
//! [pe + 0x5C, pe + 0x98 + extra)         rest of the optional header
//! [pe + 0x98 + extra, pe + 0xA0 + extra) EXCLUDED — Certificate Table entry
//! [pe + 0xA0 + extra, cert_table_addr)   everything up to the signature
//! ```
//!
//! where `pe` is the PE header offset (`e_lfanew`) and `extra` is 16
//! for PE32+ (`0x20B`) and 0 otherwise. Bytes **after** the
//! certificate table are not hashed (the C++ assumes the signature is
//! at the end of the file). Every offset is computed with checked
//! arithmetic and a hostile / truncated image yields an error instead
//! of a partial digest.
//!
//! The PKCS#7 `SignedData` is walked with a bounded DER reader (no
//! OpenSSL): the `SpcIndirectDataContent` (`1.3.6.1.4.1.311.2.1.4`)
//! `messageDigest` (algorithm + digest), the `SignerInfo` and its
//! `pkcs9 messageDigest` attribute, and nested Authenticode signatures
//! (`1.3.6.1.4.1.311.2.4.1`, bounded depth). [`VerifyStatus`] mirrors
//! the C++ `AuthenticodeVFY` values; [`VerifyStatus::Valid`] means the
//! structure parsed and the stored digest matches the file digest —
//! the X.509 chain / RSA verification of `SignerInfo`
//! (`AuthenticodeVerify`) is the `webpki` / `openssl` mapping of §5.5
//! and is not part of this module.
//!
//! Discrepancies with the C++ (all on malformed input):
//!
//! - `AuthenticodeDigest` hashes `0x3c + extra` bytes from a scratch
//!   buffer even when `BIO_read` returned fewer (the cert table lies
//!   inside the optional header); here that is
//!   [`AuthenticodeError::CertificateTableInsideHeaders`].
//! - `dwLength - 8` underflows for `dwLength < 8`; here it is
//!   [`AuthenticodeError::CertificateTruncated`].

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// `dos_hdr_size`: the image must be at least this long.
pub const DOS_HEADER_SIZE: u64 = 0x40;
/// `MZ`.
pub const DOS_SIGNATURE: [u8; 2] = [0x4D, 0x5A];
/// `pe_hdr_ptr_offset`: `e_lfanew`.
pub const PE_HEADER_PTR_OFFSET: u64 = 0x3C;
/// Optional header magic relative to the PE header (`peOffset + 0x18`).
pub const OPTIONAL_MAGIC_OFFSET: u64 = 0x18;
/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`.
pub const PE32PLUS_MAGIC: u16 = 0x20B;
/// `pe64_extra`: the 64-bit optional header is 16 bytes larger.
pub const PE64_EXTRA: u64 = 16;
/// `CheckSum` relative to the PE header (`pe_hdr_offset + 0x58`).
pub const CHECKSUM_OFFSET: u64 = 0x58;
/// Size of the excluded `CheckSum` field.
pub const CHECKSUM_SIZE: u64 = 4;
/// Bytes between the checksum and the certificate table entry
/// (`cert_table_offset = 0x3c + pe64_extra`).
pub const CHECKSUM_TO_CERT_TABLE: u64 = 0x3C;
/// Certificate table directory entry relative to the PE header
/// (`peOffset + pe64_extra + 0x98`).
pub const CERT_TABLE_DIRECTORY_OFFSET: u64 = 0x98;
/// Size of the excluded certificate table directory entry.
pub const CERT_TABLE_DIRECTORY_SIZE: u64 = 8;
/// `offsetof(WIN_CERTIFICATE, bCertificate)`.
pub const WIN_CERTIFICATE_HEADER_SIZE: u64 = 8;
/// `WIN_CERT_REVISION_2_0`.
pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;
/// `WIN_CERT_TYPE_PKCS_SIGNED_DATA`.
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
/// Hashing chunk (`buffer_size = 0xFFFF`).
pub const DIGEST_CHUNK_SIZE: usize = 0xFFFF;
/// Bound on nested-signature recursion (`ParseNestedAuthenticode`).
pub const MAX_NESTED_DEPTH: usize = 8;
/// Largest digest handled (`EVP_MAX_MD_SIZE`).
pub const MAX_DIGEST_SIZE: usize = 64;

/// DER-encoded object identifiers the parser recognises.
pub mod oid {
    /// `1.2.840.113549.1.7.2` — PKCS#7 `signedData`.
    pub const SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
    /// `1.3.6.1.4.1.311.2.1.4` — `SpcIndirectDataContent`.
    pub const SPC_INDIRECT_DATA: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
    /// `1.3.6.1.4.1.311.2.4.1` — nested Authenticode signature.
    pub const SPC_NESTED_SIGNATURE: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01];
    /// `1.3.6.1.4.1.311.3.3.1` — Microsoft counter-signature.
    pub const SPC_MS_COUNTERSIGNATURE: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01];
    /// `1.2.840.113549.1.9.4` — PKCS#9 `messageDigest`.
    pub const PKCS9_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
    /// `1.2.840.113549.2.5` — MD5.
    pub const MD5: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05];
    /// `1.3.14.3.2.26` — SHA-1.
    pub const SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
    /// `2.16.840.1.101.3.4.2.1` — SHA-256.
    pub const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    /// `2.16.840.1.101.3.4.2.2` — SHA-384.
    pub const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    /// `2.16.840.1.101.3.4.2.3` — SHA-512.
    pub const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

    /// Dotted-decimal rendering of a DER OID body (bounded; an arc
    /// wider than 64 bits is reported as `?`).
    #[must_use]
    pub fn to_dotted(body: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut out = String::new();
        let mut arc: u64 = 0;
        let mut first = true;
        let mut overflow = false;
        for &b in body {
            if arc > (u64::MAX >> 7) {
                overflow = true;
                arc = 0;
            } else {
                arc = (arc << 7) | u64::from(b & 0x7F);
            }
            if b & 0x80 != 0 {
                continue;
            }
            if overflow {
                out.push_str(if first { "?" } else { ".?" });
            } else if first {
                let (a, b2) = if arc < 40 {
                    (0, arc)
                } else if arc < 80 {
                    (1, arc.saturating_sub(40))
                } else {
                    (2, arc.saturating_sub(80))
                };
                let _ = write!(out, "{a}.{b2}");
            } else {
                let _ = write!(out, ".{arc}");
            }
            first = false;
            arc = 0;
            overflow = false;
        }
        out
    }
}

/// Digest algorithms named by `SpcIndirectDataContent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// MD5 (16 bytes).
    Md5,
    /// SHA-1 (20 bytes).
    Sha1,
    /// SHA-256 (32 bytes).
    Sha256,
    /// SHA-384 (48 bytes).
    Sha384,
    /// SHA-512 (64 bytes).
    Sha512,
}

impl DigestAlgorithm {
    /// Maps a DER OID body to an algorithm.
    #[must_use]
    pub fn from_oid(body: &[u8]) -> Option<Self> {
        match body {
            b if b == oid::MD5 => Some(Self::Md5),
            b if b == oid::SHA1 => Some(Self::Sha1),
            b if b == oid::SHA256 => Some(Self::Sha256),
            b if b == oid::SHA384 => Some(Self::Sha384),
            b if b == oid::SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Inverse of [`Self::name`] (`EVP_get_digestbyname`).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "md5" => Some(Self::Md5),
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// OpenSSL long name (`OBJ_nid2ln`), as stored in `digestAlg`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// Digest length in bytes (`EVP_MD_get_size`).
    #[must_use]
    pub const fn size(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// Incremental digest over one of the supported algorithms.
enum Hasher {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    fn new(alg: DigestAlgorithm) -> Self {
        match alg {
            DigestAlgorithm::Md5 => Self::Md5(Md5::new()),
            DigestAlgorithm::Sha1 => Self::Sha1(Sha1::new()),
            DigestAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            DigestAlgorithm::Sha384 => Self::Sha384(Sha384::new()),
            DigestAlgorithm::Sha512 => Self::Sha512(Sha512::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Md5(h) => h.update(data),
            Self::Sha1(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            Self::Md5(h) => h.finalize().to_vec(),
            Self::Sha1(h) => h.finalize().to_vec(),
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Sha384(h) => h.finalize().to_vec(),
            Self::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// C++ `AuthenticodeVFY`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum VerifyStatus {
    /// Structure parsed and the file digest matches.
    Valid = 0,
    /// Parsing error.
    CantParse = 1,
    /// Signer certificate missing.
    NoSignerCert = 2,
    /// No digest saved inside the signature.
    DigestMissing = 3,
    /// Non-verification error.
    InternalError = 4,
    /// `SignerInfo` missing.
    NoSignerInfo = 5,
    /// PKCS#7 is not `SignedData`.
    WrongPkcs7Type = 6,
    /// PKCS#7 content is not `SpcIndirectDataContent`.
    BadContent = 7,
    /// Contained and calculated digests do not match.
    Invalid = 8,
    /// Signature hash and file hash do not match.
    WrongFileDigest = 9,
    /// Unknown digest algorithm.
    UnknownAlgorithm = 10,
}

impl VerifyStatus {
    /// C++ `GetSignatureFlagName`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Valid => "Valid",
            Self::CantParse => "CantParse",
            Self::NoSignerCert => "NoSignerCert",
            Self::DigestMissing => "DigestMissing",
            Self::InternalError => "InternalError",
            Self::NoSignerInfo => "NoSignerInfo",
            Self::WrongPkcs7Type => "WrongPKCS7Type",
            Self::BadContent => "BadContent",
            Self::Invalid => "Invalid",
            Self::WrongFileDigest => "WrongFileDigest",
            Self::UnknownAlgorithm => "UnknownAlgorithm",
        }
    }
}

/// Failures of [`parse`] / [`locate`] / [`compute_file_digest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthenticodeError {
    /// Shorter than the DOS header.
    TooShort,
    /// No `MZ` signature.
    NotMz,
    /// PE header / optional-header magic outside the image.
    HeadersTruncated,
    /// Certificate table directory entry outside the image.
    CertificateDirectoryTruncated,
    /// `Security` directory absent or shorter than a
    /// `WIN_CERTIFICATE` header.
    NoCertificateTable,
    /// `WIN_CERTIFICATE` extends past the image or `dwLength < 8`.
    CertificateTruncated,
    /// The certificate table starts before the end of the excluded
    /// header fields, so no digest can be formed.
    CertificateTableInsideHeaders,
    /// Arithmetic overflow while laying out the image.
    Overflow,
}

impl core::fmt::Display for AuthenticodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::TooShort => "image shorter than the DOS header",
            Self::NotMz => "missing MZ signature",
            Self::HeadersTruncated => "PE headers truncated",
            Self::CertificateDirectoryTruncated => "certificate table directory entry truncated",
            Self::NoCertificateTable => "no embedded certificate table",
            Self::CertificateTruncated => "WIN_CERTIFICATE truncated",
            Self::CertificateTableInsideHeaders => "certificate table overlaps the PE headers",
            Self::Overflow => "offset arithmetic overflow",
        };
        f.write_str(text)
    }
}

impl std::error::Error for AuthenticodeError {}

/// The header facts `AuthenticodeParse` derives before hashing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeLayout {
    /// `e_lfanew`.
    pub pe_header_offset: u32,
    /// Optional header magic is `0x20B`.
    pub is_pe64: bool,
    /// File offset of the certificate table directory entry.
    pub cert_directory_offset: u64,
    /// `WIN_CERTIFICATE` file offset (directory `VirtualAddress`).
    pub cert_table_address: u64,
    /// Directory `Size`.
    pub cert_table_length: u64,
}

impl PeLayout {
    /// `pe64_extra`.
    #[must_use]
    pub const fn extra(&self) -> u64 {
        if self.is_pe64 {
            PE64_EXTRA
        } else {
            0
        }
    }
}

/// One `WIN_CERTIFICATE` header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WinCertificate {
    /// `dwLength` (header included).
    pub length: u32,
    /// `wRevision`.
    pub revision: u16,
    /// `wCertificateType`.
    pub certificate_type: u16,
}

/// `SpcIndirectDataContent.messageDigest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageDigest {
    /// Algorithm OID body (DER).
    pub algorithm_oid: Vec<u8>,
    /// Digest bytes.
    pub digest: Vec<u8>,
}

impl MessageDigest {
    /// The algorithm, when recognised.
    #[must_use]
    pub fn algorithm(&self) -> Option<DigestAlgorithm> {
        DigestAlgorithm::from_oid(&self.algorithm_oid)
    }

    /// `digestAlg` as the C++ stores it: the OpenSSL long name, or
    /// the dotted OID when unknown.
    #[must_use]
    pub fn algorithm_name(&self) -> String {
        self.algorithm()
            .map_or_else(|| oid::to_dotted(&self.algorithm_oid), |a| a.name().to_owned())
    }
}

/// C++ `Signer` (the parts that need no X.509 work).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Signer {
    /// `pkcs9 messageDigest` authenticated attribute.
    pub digest: Vec<u8>,
    /// `SignerInfo.digestAlgorithm` name.
    pub digest_alg: String,
}

/// C++ `AuthenticodeSignature`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticodeSignature {
    /// `verifyFlags`.
    pub status: VerifyStatus,
    /// Raw PKCS#7 `SignedData.version`.
    pub version: u64,
    /// Digest algorithm name.
    pub digest_alg: String,
    /// File digest stored in the signature.
    pub digest: Vec<u8>,
    /// Calculated file digest (empty when it could not be computed).
    pub file_digest: Vec<u8>,
    /// `SignerInfo` facts.
    pub signer: Signer,
    /// Nesting depth (0 for the top-level signature).
    pub depth: usize,
}

impl AuthenticodeSignature {
    fn with_status(status: VerifyStatus, depth: usize) -> Self {
        Self {
            status,
            version: 0,
            digest_alg: String::new(),
            digest: Vec::new(),
            file_digest: Vec::new(),
            signer: Signer::default(),
            depth,
        }
    }
}

// ---------------------------------------------------------------------------
// Bounded byte readers
// ---------------------------------------------------------------------------

fn read_u16_le(buf: &[u8], at: u64) -> Option<u16> {
    let start = usize::try_from(at).ok()?;
    let end = start.checked_add(2)?;
    let b = buf.get(start..end)?;
    Some(u16::from_le_bytes([*b.first()?, *b.get(1)?]))
}

fn read_u32_le(buf: &[u8], at: u64) -> Option<u32> {
    let start = usize::try_from(at).ok()?;
    let end = start.checked_add(4)?;
    let b = buf.get(start..end)?;
    Some(u32::from_le_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?]))
}

fn slice(buf: &[u8], start: u64, end: u64) -> Option<&[u8]> {
    let s = usize::try_from(start).ok()?;
    let e = usize::try_from(end).ok()?;
    buf.get(s..e)
}

// ---------------------------------------------------------------------------
// PE layout & digest
// ---------------------------------------------------------------------------

/// The header walk of `AuthenticodeParse` (`Authenticode.cpp:613-650`).
///
/// # Errors
///
/// [`AuthenticodeError`] for a non-PE, truncated, or unsigned image.
pub fn locate(pe: &[u8]) -> Result<PeLayout, AuthenticodeError> {
    let len = pe.len() as u64;
    if len < DOS_HEADER_SIZE {
        return Err(AuthenticodeError::TooShort);
    }
    if pe.get(..2) != Some(&DOS_SIGNATURE[..]) {
        return Err(AuthenticodeError::NotMz);
    }
    let pe_offset = read_u32_le(pe, PE_HEADER_PTR_OFFSET).ok_or(AuthenticodeError::HeadersTruncated)?;
    let magic_addr = u64::from(pe_offset)
        .checked_add(OPTIONAL_MAGIC_OFFSET)
        .ok_or(AuthenticodeError::Overflow)?;
    if len < magic_addr.checked_add(2).ok_or(AuthenticodeError::Overflow)? {
        return Err(AuthenticodeError::HeadersTruncated);
    }
    let magic = read_u16_le(pe, magic_addr).ok_or(AuthenticodeError::HeadersTruncated)?;
    let is_pe64 = magic == PE32PLUS_MAGIC;
    let extra = if is_pe64 { PE64_EXTRA } else { 0 };
    let cert_directory_offset = u64::from(pe_offset)
        .checked_add(extra)
        .and_then(|v| v.checked_add(CERT_TABLE_DIRECTORY_OFFSET))
        .ok_or(AuthenticodeError::Overflow)?;
    if len
        < cert_directory_offset
            .checked_add(CERT_TABLE_DIRECTORY_SIZE)
            .ok_or(AuthenticodeError::Overflow)?
    {
        return Err(AuthenticodeError::CertificateDirectoryTruncated);
    }
    let cert_table_address =
        u64::from(read_u32_le(pe, cert_directory_offset).ok_or(AuthenticodeError::CertificateDirectoryTruncated)?);
    let cert_table_length = u64::from(
        read_u32_le(pe, cert_directory_offset.saturating_add(4))
            .ok_or(AuthenticodeError::CertificateDirectoryTruncated)?,
    );
    // "we need at least 8 bytes to read dwLength, revision and certType"
    if cert_table_length < WIN_CERTIFICATE_HEADER_SIZE {
        return Err(AuthenticodeError::NoCertificateTable);
    }
    if len
        < cert_table_address
            .checked_add(WIN_CERTIFICATE_HEADER_SIZE)
            .ok_or(AuthenticodeError::Overflow)?
    {
        return Err(AuthenticodeError::NoCertificateTable);
    }
    Ok(PeLayout {
        pe_header_offset: pe_offset,
        is_pe64,
        cert_directory_offset,
        cert_table_address,
        cert_table_length,
    })
}

/// Reads the first `WIN_CERTIFICATE` header and returns it with its
/// `bCertificate` payload (`dwLength - 8` bytes).
///
/// # Errors
///
/// [`AuthenticodeError::CertificateTruncated`] when `dwLength` is
/// below the header size or runs past the image.
pub fn win_certificate<'a>(pe: &'a [u8], layout: &PeLayout) -> Result<(WinCertificate, &'a [u8]), AuthenticodeError> {
    let at = layout.cert_table_address;
    let length = read_u32_le(pe, at).ok_or(AuthenticodeError::CertificateTruncated)?;
    let revision = read_u16_le(pe, at.saturating_add(4)).ok_or(AuthenticodeError::CertificateTruncated)?;
    let certificate_type = read_u16_le(pe, at.saturating_add(6)).ok_or(AuthenticodeError::CertificateTruncated)?;
    let end = at.checked_add(u64::from(length)).ok_or(AuthenticodeError::Overflow)?;
    if (pe.len() as u64) < end || u64::from(length) < WIN_CERTIFICATE_HEADER_SIZE {
        return Err(AuthenticodeError::CertificateTruncated);
    }
    let payload = slice(pe, at.saturating_add(WIN_CERTIFICATE_HEADER_SIZE), end)
        .ok_or(AuthenticodeError::CertificateTruncated)?;
    Ok((
        WinCertificate {
            length,
            revision,
            certificate_type,
        },
        payload,
    ))
}

/// The three `[start, end)` byte ranges `AuthenticodeDigest` feeds to
/// the hash, in order: up to the checksum, checksum end to the
/// certificate table entry, entry end to `cert_table_addr`.
///
/// # Errors
///
/// [`AuthenticodeError::CertificateTableInsideHeaders`] when
/// `cert_table_addr` does not lie past the certificate table entry
/// (the C++ `BIO_read` failures), or [`AuthenticodeError::Overflow`].
pub fn hashed_ranges(
    pe_header_offset: u32,
    is_pe64: bool,
    cert_table_addr: u64,
) -> Result<[(u64, u64); 3], AuthenticodeError> {
    let extra = if is_pe64 { PE64_EXTRA } else { 0 };
    let pe = u64::from(pe_header_offset);
    let checksum = pe.checked_add(CHECKSUM_OFFSET).ok_or(AuthenticodeError::Overflow)?;
    let after_checksum = checksum.checked_add(CHECKSUM_SIZE).ok_or(AuthenticodeError::Overflow)?;
    let cert_entry = after_checksum
        .checked_add(CHECKSUM_TO_CERT_TABLE)
        .and_then(|v| v.checked_add(extra))
        .ok_or(AuthenticodeError::Overflow)?;
    let after_entry = cert_entry
        .checked_add(CERT_TABLE_DIRECTORY_SIZE)
        .ok_or(AuthenticodeError::Overflow)?;
    // C++: every BIO_read up to `after_entry` must return data, so the
    // certificate table has to start strictly past the entry.
    if cert_table_addr <= after_entry {
        return Err(AuthenticodeError::CertificateTableInsideHeaders);
    }
    Ok([(0, checksum), (after_checksum, cert_entry), (after_entry, cert_table_addr)])
}

/// C++ `AuthenticodeDigest`: hashes the image with the checksum and
/// certificate table entry excluded, in `0xFFFF`-byte chunks.
///
/// # Errors
///
/// As [`hashed_ranges`], plus [`AuthenticodeError::CertificateTruncated`]
/// when `cert_table_addr` is past the image.
pub fn compute_file_digest(
    alg: DigestAlgorithm,
    pe: &[u8],
    pe_header_offset: u32,
    is_pe64: bool,
    cert_table_addr: u64,
) -> Result<Vec<u8>, AuthenticodeError> {
    if (pe.len() as u64) < cert_table_addr {
        return Err(AuthenticodeError::CertificateTruncated);
    }
    let ranges = hashed_ranges(pe_header_offset, is_pe64, cert_table_addr)?;
    let mut hasher = Hasher::new(alg);
    for (start, end) in ranges {
        let bytes = slice(pe, start, end).ok_or(AuthenticodeError::CertificateTruncated)?;
        for chunk in bytes.chunks(DIGEST_CHUNK_SIZE) {
            hasher.update(chunk);
        }
    }
    Ok(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Minimal DER
// ---------------------------------------------------------------------------

/// DER tags used here.
mod tag {
    pub const INTEGER: u8 = 0x02;
    pub const OCTET_STRING: u8 = 0x04;
    pub const OID: u8 = 0x06;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
    pub const CONTEXT_0: u8 = 0xA0;
    pub const CONTEXT_1: u8 = 0xA1;
}

/// One decoded TLV.
#[derive(Clone, Copy, Debug)]
struct Tlv<'a> {
    tag: u8,
    body: &'a [u8],
    /// Header + body bytes, i.e. the whole encoding of this element.
    raw: &'a [u8],
}

/// Decodes the TLV at the start of `buf` (definite lengths only).
fn tlv(buf: &[u8]) -> Option<Tlv<'_>> {
    let tag = *buf.first()?;
    let first = *buf.get(1)?;
    let (len, header) = if first & 0x80 == 0 {
        (usize::from(first), 2_usize)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0_usize;
        for i in 0..n {
            let b = *buf.get(2_usize.checked_add(i)?)?;
            len = len.checked_shl(8)?.checked_add(usize::from(b))?;
        }
        (len, 2_usize.checked_add(n)?)
    };
    let end = header.checked_add(len)?;
    let raw = buf.get(..end)?;
    let body = raw.get(header..)?;
    Some(Tlv { tag, body, raw })
}

/// Iterates the TLVs inside a constructed body.
struct Children<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Children<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Tlv<'a>> {
        if self.rest.is_empty() {
            return None;
        }
        let item = tlv(self.rest)?;
        self.rest = self.rest.get(item.raw.len()..)?;
        Some(item)
    }
}

const fn children(body: &[u8]) -> Children<'_> {
    Children { rest: body }
}

fn expect(buf: &[u8], want: u8) -> Option<Tlv<'_>> {
    let item = tlv(buf)?;
    (item.tag == want).then_some(item)
}

/// Unsigned INTEGER body to `u64` (saturating when wider).
fn integer_u64(body: &[u8]) -> u64 {
    let mut v = 0_u64;
    for &b in body {
        if v > (u64::MAX >> 8) {
            return u64::MAX;
        }
        v = (v << 8) | u64::from(b);
    }
    v
}

/// `SpcIndirectDataContent ::= SEQUENCE { data, messageDigest DigestInfo }`;
/// `DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }`.
fn parse_spc_indirect_data(body: &[u8]) -> Option<MessageDigest> {
    let outer = expect(body, tag::SEQUENCE)?;
    let mut items = children(outer.body);
    let _data = items.next().filter(|t| t.tag == tag::SEQUENCE)?;
    let digest_info = items.next().filter(|t| t.tag == tag::SEQUENCE)?;
    let mut di = children(digest_info.body);
    let algorithm = di.next().filter(|t| t.tag == tag::SEQUENCE)?;
    let algorithm_oid = children(algorithm.body).next().filter(|t| t.tag == tag::OID)?;
    let digest = di.next().filter(|t| t.tag == tag::OCTET_STRING)?;
    Some(MessageDigest {
        algorithm_oid: algorithm_oid.body.to_vec(),
        digest: digest.body.to_vec(),
    })
}

/// Decoded `SignerInfo` facts.
struct SignerInfo<'a> {
    digest_alg_oid: &'a [u8],
    message_digest: Option<&'a [u8]>,
    nested: Vec<&'a [u8]>,
}

/// `Attribute ::= SEQUENCE { type OID, values SET }` → `(type, values)`.
fn attribute(attr: Tlv<'_>) -> Option<(&[u8], &[u8])> {
    let mut parts = children(attr.body);
    let attr_oid = parts.next().filter(|t| t.tag == tag::OID)?;
    let values = parts.next().filter(|t| t.tag == tag::SET)?;
    Some((attr_oid.body, values.body))
}

/// `SignerInfo ::= SEQUENCE { version, issuerAndSerialNumber, digestAlgorithm,
/// [0] authenticatedAttributes, digestEncryptionAlgorithm, encryptedDigest,
/// [1] unauthenticatedAttributes }`.
fn parse_signer_info(body: &[u8]) -> Option<SignerInfo<'_>> {
    let mut items = children(body);
    let _version = items.next().filter(|t| t.tag == tag::INTEGER)?;
    let _issuer = items.next().filter(|t| t.tag == tag::SEQUENCE)?;
    let digest_alg = items.next().filter(|t| t.tag == tag::SEQUENCE)?;
    let digest_alg_oid = children(digest_alg.body).next().filter(|t| t.tag == tag::OID)?.body;
    let mut message_digest = None;
    let mut nested = Vec::new();
    for item in items {
        match item.tag {
            tag::CONTEXT_0 => {
                for (attr_oid, values) in children(item.body).filter_map(attribute) {
                    if attr_oid == oid::PKCS9_MESSAGE_DIGEST {
                        if let Some(v) = children(values).next().filter(|t| t.tag == tag::OCTET_STRING) {
                            message_digest = Some(v.body);
                        }
                    }
                }
            }
            tag::CONTEXT_1 => {
                for (attr_oid, values) in children(item.body).filter_map(attribute) {
                    if attr_oid == oid::SPC_NESTED_SIGNATURE {
                        // Each value is a whole ContentInfo (PKCS#7).
                        nested.extend(children(values).filter(|t| t.tag == tag::SEQUENCE).map(|t| t.raw));
                    }
                }
            }
            _ => {}
        }
    }
    Some(SignerInfo {
        digest_alg_oid,
        message_digest,
        nested,
    })
}

/// C++ `AuthenticodeParseSignature` (+ `ParseNestedAuthenticode`):
/// walks one PKCS#7 `ContentInfo` and pushes the resulting
/// [`AuthenticodeSignature`]s (nested ones first, as the C++ does).
/// The file digest is left empty; [`parse`] fills it in.
fn parse_signature(der: &[u8], depth: usize, out: &mut Vec<AuthenticodeSignature>) {
    if depth > MAX_NESTED_DEPTH {
        return;
    }
    let fail = |status: VerifyStatus, out: &mut Vec<AuthenticodeSignature>| {
        out.push(AuthenticodeSignature::with_status(status, depth));
    };
    // ContentInfo ::= SEQUENCE { contentType OID, [0] EXPLICIT content }
    let Some(content_info) = expect(der, tag::SEQUENCE) else {
        return fail(VerifyStatus::CantParse, out);
    };
    let mut ci = children(content_info.body);
    let Some(content_type) = ci.next().filter(|t| t.tag == tag::OID) else {
        return fail(VerifyStatus::CantParse, out);
    };
    if content_type.body != oid::SIGNED_DATA {
        return fail(VerifyStatus::WrongPkcs7Type, out);
    }
    let Some(signed_data) = ci
        .next()
        .filter(|t| t.tag == tag::CONTEXT_0)
        .and_then(|t| expect(t.body, tag::SEQUENCE))
    else {
        return fail(VerifyStatus::CantParse, out);
    };
    // SignedData ::= SEQUENCE { version, digestAlgorithms SET, contentInfo,
    //                           [0] certs, [1] crls, signerInfos SET }
    let mut sd = children(signed_data.body);
    let Some(version) = sd.next().filter(|t| t.tag == tag::INTEGER) else {
        return fail(VerifyStatus::CantParse, out);
    };
    let Some(_digest_algorithms) = sd.next().filter(|t| t.tag == tag::SET) else {
        return fail(VerifyStatus::CantParse, out);
    };
    let Some(content) = sd.next().filter(|t| t.tag == tag::SEQUENCE) else {
        return fail(VerifyStatus::CantParse, out);
    };
    let mut auth = AuthenticodeSignature::with_status(VerifyStatus::Valid, depth);
    auth.version = integer_u64(version.body);

    // GetContent: contentType must be SpcIndirectDataContent.
    let mut c = children(content.body);
    let message_digest = c
        .next()
        .filter(|t| t.tag == tag::OID && t.body == oid::SPC_INDIRECT_DATA)
        .and_then(|_| c.next().filter(|t| t.tag == tag::CONTEXT_0))
        .and_then(|t| parse_spc_indirect_data(t.body));
    let Some(message_digest) = message_digest else {
        auth.status = VerifyStatus::BadContent;
        out.push(auth);
        return;
    };
    auth.digest_alg = message_digest.algorithm_name();
    auth.digest = message_digest.digest;

    // Skip [0] certificates / [1] crls; signerInfos is the SET.
    let signer = sd
        .find(|t| t.tag == tag::SET)
        .and_then(|set| children(set.body).next())
        .filter(|t| t.tag == tag::SEQUENCE)
        .and_then(|t| parse_signer_info(t.body));
    let Some(si) = signer else {
        auth.status = VerifyStatus::NoSignerInfo;
        out.push(auth);
        return;
    };
    // Nested signatures are appended before the outer one (C++ order).
    for nested in &si.nested {
        parse_signature(nested, depth.saturating_add(1), out);
    }
    let Some(signer_digest) = si.message_digest else {
        auth.status = VerifyStatus::DigestMissing;
        out.push(auth);
        return;
    };
    auth.signer = Signer {
        digest: signer_digest.to_vec(),
        digest_alg: DigestAlgorithm::from_oid(si.digest_alg_oid)
            .map_or_else(|| oid::to_dotted(si.digest_alg_oid), |a| a.name().to_owned()),
    };
    out.push(auth);
}

/// C++ `AuthenticodeParser::AuthenticodeParse`: locates the
/// certificate table, parses the first `WIN_CERTIFICATE` PKCS#7 and
/// compares every signature's stored digest with the file digest.
///
/// # Errors
///
/// [`AuthenticodeError`] when the image is not a PE, is truncated, or
/// carries no certificate table (the C++ `return false` cases).
pub fn parse(pe: &[u8]) -> Result<Vec<AuthenticodeSignature>, AuthenticodeError> {
    let layout = locate(pe)?;
    let (_certificate, payload) = win_certificate(pe, &layout)?;
    let mut signatures = Vec::new();
    parse_signature(payload, 0, &mut signatures);

    for sig in &mut signatures {
        let named = DigestAlgorithm::from_name(&sig.digest_alg);
        let Some(alg) = named.filter(|_| !sig.digest.is_empty()) else {
            if sig.status == VerifyStatus::Valid {
                sig.status = VerifyStatus::UnknownAlgorithm;
            }
            continue;
        };
        let computed = compute_file_digest(alg, pe, layout.pe_header_offset, layout.is_pe64, layout.cert_table_address);
        let Ok(file_digest) = computed else {
            if sig.status == VerifyStatus::Valid {
                sig.status = VerifyStatus::InternalError;
            }
            break;
        };
        if file_digest.get(..alg.size()) != sig.digest.get(..alg.size()) {
            sig.status = VerifyStatus::WrongFileDigest;
        }
        sig.file_digest = file_digest;
    }
    Ok(signatures)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // --- DER builders -----------------------------------------------------

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = body.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.extend_from_slice(&[0x81, len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        }
        out.extend_from_slice(body);
        out
    }

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        der(tag::SEQUENCE, &parts.concat())
    }

    fn set(parts: &[Vec<u8>]) -> Vec<u8> {
        der(tag::SET, &parts.concat())
    }

    fn alg_id(oid_body: &[u8]) -> Vec<u8> {
        seq(&[der(tag::OID, oid_body), vec![0x05, 0x00]])
    }

    fn spc_content(alg: &[u8], digest: &[u8]) -> Vec<u8> {
        let spc = seq(&[
            seq(&[
                der(tag::OID, &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F]),
                vec![0x05, 0x00],
            ]),
            seq(&[alg_id(alg), der(tag::OCTET_STRING, digest)]),
        ]);
        seq(&[der(tag::OID, oid::SPC_INDIRECT_DATA), der(tag::CONTEXT_0, &spc)])
    }

    fn signer_info(alg: &[u8], signer_digest: Option<&[u8]>, nested: &[Vec<u8>]) -> Vec<u8> {
        let mut auth_attrs = vec![seq(&[
            der(tag::OID, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03]),
            set(&[der(tag::OID, oid::SPC_INDIRECT_DATA)]),
        ])];
        if let Some(d) = signer_digest {
            auth_attrs.push(seq(&[
                der(tag::OID, oid::PKCS9_MESSAGE_DIGEST),
                set(&[der(tag::OCTET_STRING, d)]),
            ]));
        }
        let mut parts = vec![
            der(tag::INTEGER, &[1]),
            seq(&[seq(&[]), der(tag::INTEGER, &[0x42])]),
            alg_id(alg),
            der(tag::CONTEXT_0, &auth_attrs.concat()),
            alg_id(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]),
            der(tag::OCTET_STRING, &[0xAA; 16]),
        ];
        if !nested.is_empty() {
            parts.push(der(
                tag::CONTEXT_1,
                &seq(&[der(tag::OID, oid::SPC_NESTED_SIGNATURE), set(nested)]),
            ));
        }
        seq(&parts)
    }

    /// A PKCS#7 `SignedData` carrying `digest` for `alg`, optionally with
    /// nested signatures in the unauthenticated attributes.
    fn pkcs7(alg: &[u8], digest: &[u8], signer_digest: Option<&[u8]>, nested: &[Vec<u8>]) -> Vec<u8> {
        let signed_data = seq(&[
            der(tag::INTEGER, &[1]),
            set(&[alg_id(alg)]),
            spc_content(alg, digest),
            der(tag::CONTEXT_0, &seq(&[der(tag::INTEGER, &[2]), seq(&[]), seq(&[])])),
            set(&[signer_info(alg, signer_digest, nested)]),
        ]);
        seq(&[der(tag::OID, oid::SIGNED_DATA), der(tag::CONTEXT_0, &signed_data)])
    }

    // --- PE builders ------------------------------------------------------

    const LFANEW: u32 = 0x80;

    /// An unsigned PE image of `body_len` bytes with the given
    /// optional-header magic and a filler pattern.
    fn unsigned_pe(pe64: bool, body_len: usize) -> Vec<u8> {
        let mut image = vec![0_u8; body_len];
        for (i, b) in image.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        image[0..2].copy_from_slice(&DOS_SIGNATURE);
        image[0x3C..0x40].copy_from_slice(&LFANEW.to_le_bytes());
        let pe = LFANEW as usize;
        image[pe..pe + 4].copy_from_slice(b"PE\0\0");
        let magic: u16 = if pe64 { PE32PLUS_MAGIC } else { 0x10B };
        image[pe + 0x18..pe + 0x1A].copy_from_slice(&magic.to_le_bytes());
        image[pe + 0x58..pe + 0x5C].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        let extra = if pe64 { 16 } else { 0 };
        let dir = pe + extra + 0x98;
        image[dir..dir + 8].fill(0);
        image
    }

    /// Appends a `WIN_CERTIFICATE` with `pkcs7` and points the Security
    /// directory at it.
    fn sign(mut image: Vec<u8>, pe64: bool, pkcs7: &[u8]) -> Vec<u8> {
        let cert_addr = image.len() as u32;
        let length = 8 + pkcs7.len() as u32;
        image.extend_from_slice(&length.to_le_bytes());
        image.extend_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes());
        image.extend_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
        image.extend_from_slice(pkcs7);
        let dir = LFANEW as usize + if pe64 { 16 } else { 0 } + 0x98;
        image[dir..dir + 4].copy_from_slice(&cert_addr.to_le_bytes());
        image[dir + 4..dir + 8].copy_from_slice(&length.to_le_bytes());
        image
    }

    /// The reference digest: concatenate the ranges by hand.
    fn reference_digest(alg: DigestAlgorithm, image: &[u8], pe64: bool, cert_addr: usize) -> Vec<u8> {
        let pe = LFANEW as usize;
        let extra = if pe64 { 16 } else { 0 };
        let mut data = Vec::new();
        data.extend_from_slice(&image[..pe + 0x58]);
        data.extend_from_slice(&image[pe + 0x5C..pe + 0x98 + extra]);
        data.extend_from_slice(&image[pe + 0xA0 + extra..cert_addr]);
        let mut h = Hasher::new(alg);
        h.update(&data);
        h.finalize()
    }

    fn signed_image(pe64: bool, alg: DigestAlgorithm, alg_oid: &[u8], body_len: usize) -> (Vec<u8>, Vec<u8>) {
        let unsigned = unsigned_pe(pe64, body_len);
        let expected = reference_digest(alg, &unsigned, pe64, unsigned.len());
        let p7 = pkcs7(alg_oid, &expected, Some(&[0x11; 32]), &[]);
        (sign(unsigned, pe64, &p7), expected)
    }

    // --- Tests ------------------------------------------------------------

    #[test]
    fn hashed_ranges_exclude_checksum_and_cert_table_entry() {
        let r = hashed_ranges(0x80, false, 0x1000).expect("ranges");
        assert_eq!(r, [(0, 0xD8), (0xDC, 0x118), (0x120, 0x1000)]);
        let r64 = hashed_ranges(0x80, true, 0x1000).expect("ranges");
        assert_eq!(r64, [(0, 0xD8), (0xDC, 0x128), (0x130, 0x1000)]);
        // Holes: 4 bytes at pe+0x58 and 8 bytes at pe+0x98(+16).
        assert_eq!(r[0].1, 0x80 + CHECKSUM_OFFSET);
        assert_eq!(r[0].1 + CHECKSUM_SIZE, r[1].0);
        assert_eq!(r[1].1, 0x80 + CERT_TABLE_DIRECTORY_OFFSET);
        assert_eq!(r[1].1 + CERT_TABLE_DIRECTORY_SIZE, r[2].0);
        assert_eq!(r64[1].1, 0x80 + PE64_EXTRA + CERT_TABLE_DIRECTORY_OFFSET);
        // Cert table inside the headers cannot be hashed.
        assert_eq!(
            hashed_ranges(0x80, false, 0x120),
            Err(AuthenticodeError::CertificateTableInsideHeaders)
        );
        assert_eq!(hashed_ranges(0x80, false, 0), Err(AuthenticodeError::CertificateTableInsideHeaders));
        assert!(hashed_ranges(0x80, false, 0x121).is_ok());
        assert!(hashed_ranges(u32::MAX, true, u64::MAX).is_ok());
    }

    #[test]
    fn digest_matches_reference_for_pe32_and_pe32plus_all_algorithms() {
        for pe64 in [false, true] {
            for (alg, oid_body) in [
                (DigestAlgorithm::Md5, oid::MD5),
                (DigestAlgorithm::Sha1, oid::SHA1),
                (DigestAlgorithm::Sha256, oid::SHA256),
                (DigestAlgorithm::Sha384, oid::SHA384),
                (DigestAlgorithm::Sha512, oid::SHA512),
            ] {
                let (image, expected) = signed_image(pe64, alg, oid_body, 0x3_0000 + 13);
                let layout = locate(&image).expect("layout");
                assert_eq!(layout.is_pe64, pe64);
                assert_eq!(layout.extra(), if pe64 { 16 } else { 0 });
                assert_eq!(layout.pe_header_offset, LFANEW);
                assert_eq!(layout.cert_table_address, 0x3_0000 + 13);
                let got = compute_file_digest(alg, &image, LFANEW, pe64, layout.cert_table_address).expect("digest");
                assert_eq!(got, expected, "{alg:?} pe64={pe64}");
                assert_eq!(got.len(), alg.size());

                let sigs = parse(&image).expect("parse");
                assert_eq!(sigs.len(), 1);
                assert_eq!(sigs[0].status, VerifyStatus::Valid, "{alg:?} pe64={pe64}");
                assert_eq!(sigs[0].digest_alg, alg.name());
                assert_eq!(sigs[0].digest, expected);
                assert_eq!(sigs[0].file_digest, expected);
                assert_eq!(sigs[0].version, 1);
                assert_eq!(sigs[0].depth, 0);
                assert_eq!(sigs[0].signer.digest, vec![0x11; 32]);
                assert_eq!(sigs[0].signer.digest_alg, alg.name());
            }
        }
    }

    #[test]
    fn checksum_and_cert_entry_changes_do_not_affect_digest_but_body_does() {
        let (image, expected) = signed_image(false, DigestAlgorithm::Sha256, oid::SHA256, 0x800);
        let pe = LFANEW as usize;
        // Flip the checksum: still valid.
        let mut tampered = image.clone();
        tampered[pe + 0x58..pe + 0x5C].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(parse(&tampered).expect("parse")[0].status, VerifyStatus::Valid);
        // Change the certificate table *size* (inside the excluded
        // entry; the address is untouched): still valid.
        let mut tampered = image.clone();
        let dir = pe + 0x98;
        tampered[dir + 6] = 0x7F;
        tampered[dir + 7] = 0x7F;
        assert_eq!(parse(&tampered).expect("parse")[0].status, VerifyStatus::Valid);
        // Flip a body byte: WrongFileDigest.
        let mut tampered = image.clone();
        tampered[0x400] ^= 0xFF;
        let sigs = parse(&tampered).expect("parse");
        assert_eq!(sigs[0].status, VerifyStatus::WrongFileDigest);
        assert_ne!(sigs[0].file_digest, expected);
        assert_eq!(sigs[0].digest, expected);
        // Flip a DOS stub byte between the headers: WrongFileDigest.
        let mut tampered = image.clone();
        tampered[0x50] ^= 0x01;
        assert_eq!(parse(&tampered).expect("parse")[0].status, VerifyStatus::WrongFileDigest);
        // A byte of the optional header outside the holes counts.
        let mut tampered = image.clone();
        tampered[pe + 0x5C] ^= 0x01;
        assert_eq!(parse(&tampered).expect("parse")[0].status, VerifyStatus::WrongFileDigest);
        let mut tampered = image.clone();
        tampered[pe + 0xA0] ^= 0x01;
        assert_eq!(parse(&tampered).expect("parse")[0].status, VerifyStatus::WrongFileDigest);
        // Bytes after the signature are not hashed.
        let mut trailing = image;
        trailing.extend_from_slice(b"overlay after the signature");
        assert_eq!(parse(&trailing).expect("parse")[0].status, VerifyStatus::Valid);
    }

    #[test]
    fn chunked_hashing_matches_single_shot_over_large_images() {
        // Larger than 0xFFFF so the chunk loop runs several times.
        let size = 0x2_0000 + 0x1234;
        let (image, expected) = signed_image(true, DigestAlgorithm::Sha1, oid::SHA1, size);
        let got = compute_file_digest(DigestAlgorithm::Sha1, &image, LFANEW, true, size as u64).expect("digest");
        assert_eq!(got, expected);
    }

    #[test]
    fn locate_rejects_non_pe_and_unsigned_images() {
        assert_eq!(locate(b"MZ"), Err(AuthenticodeError::TooShort));
        assert_eq!(locate(&[0_u8; 64]), Err(AuthenticodeError::NotMz));
        let mut short = vec![0_u8; 64];
        short[0..2].copy_from_slice(b"MZ");
        short[0x3C..0x40].copy_from_slice(&0x1000_u32.to_le_bytes());
        assert_eq!(locate(&short), Err(AuthenticodeError::HeadersTruncated));
        // Headers present but no certificate directory bytes.
        let mut cut = unsigned_pe(false, 0x200);
        cut.truncate(0x80 + 0x9C);
        assert_eq!(locate(&cut), Err(AuthenticodeError::CertificateDirectoryTruncated));
        // Unsigned: directory zero.
        assert_eq!(locate(&unsigned_pe(false, 0x400)), Err(AuthenticodeError::NoCertificateTable));
        assert_eq!(parse(&unsigned_pe(true, 0x400)), Err(AuthenticodeError::NoCertificateTable));
        // Directory points past the file.
        let mut past = unsigned_pe(false, 0x400);
        let dir = 0x80 + 0x98;
        past[dir..dir + 4].copy_from_slice(&0x1_0000_u32.to_le_bytes());
        past[dir + 4..dir + 8].copy_from_slice(&0x100_u32.to_le_bytes());
        assert_eq!(locate(&past), Err(AuthenticodeError::NoCertificateTable));
        // e_lfanew far past the image.
        let mut huge = unsigned_pe(false, 0x400);
        huge[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(locate(&huge), Err(AuthenticodeError::HeadersTruncated));
    }

    #[test]
    fn win_certificate_bounds_are_checked() {
        let (image, _) = signed_image(false, DigestAlgorithm::Sha256, oid::SHA256, 0x800);
        let layout = locate(&image).expect("layout");
        let (cert, payload) = win_certificate(&image, &layout).expect("cert");
        assert_eq!(cert.revision, WIN_CERT_REVISION_2_0);
        assert_eq!(cert.certificate_type, WIN_CERT_TYPE_PKCS_SIGNED_DATA);
        assert_eq!(u64::from(cert.length), 8 + payload.len() as u64);
        assert_eq!(layout.cert_table_length, u64::from(cert.length));
        // dwLength past the image.
        let mut long = image.clone();
        let at = layout.cert_table_address as usize;
        long[at..at + 4].copy_from_slice(&0xFFFF_u32.to_le_bytes());
        assert_eq!(
            win_certificate(&long, &layout).map(|(c, _)| c),
            Err(AuthenticodeError::CertificateTruncated)
        );
        assert_eq!(parse(&long), Err(AuthenticodeError::CertificateTruncated));
        // dwLength < 8 (C++ underflow case).
        let mut tiny = image.clone();
        tiny[at..at + 4].copy_from_slice(&4_u32.to_le_bytes());
        assert_eq!(
            win_certificate(&tiny, &layout).map(|(c, _)| c),
            Err(AuthenticodeError::CertificateTruncated)
        );
        // Certificate table inside the headers: digest impossible.
        let mut inside = image.clone();
        let dir = 0x80 + 0x98;
        inside[dir..dir + 4].copy_from_slice(&0x100_u32.to_le_bytes());
        inside[0x100..0x104].copy_from_slice(&(8 + 4_u32).to_le_bytes());
        assert_eq!(
            compute_file_digest(DigestAlgorithm::Sha256, &inside, LFANEW, false, 0x100),
            Err(AuthenticodeError::CertificateTableInsideHeaders)
        );
        let sigs = parse(&inside).expect("parse still succeeds");
        assert_eq!(sigs[0].status, VerifyStatus::CantParse);
        // Same but with a well-formed PKCS#7 at that spot: InternalError.
        let unsigned = unsigned_pe(false, 0x800);
        let p7 = pkcs7(oid::SHA256, &[0; 32], Some(&[0; 32]), &[]);
        let mut early = unsigned;
        // Exactly at the end of the excluded entry (0x80 + 0xA0).
        early[dir..dir + 4].copy_from_slice(&0x120_u32.to_le_bytes());
        early[dir + 4..dir + 8].copy_from_slice(&((8 + p7.len()) as u32).to_le_bytes());
        early[0x120..0x124].copy_from_slice(&((8 + p7.len()) as u32).to_le_bytes());
        early[0x128..0x128 + p7.len()].copy_from_slice(&p7);
        let sigs = parse(&early).expect("parse");
        assert_eq!(sigs[0].status, VerifyStatus::InternalError);
        assert!(sigs[0].file_digest.is_empty());
    }

    #[test]
    fn pkcs7_structure_errors_map_to_verify_flags() {
        let unsigned = unsigned_pe(false, 0x800);
        let expected = reference_digest(DigestAlgorithm::Sha256, &unsigned, false, unsigned.len());
        // Garbage payload.
        let image = sign(unsigned.clone(), false, b"\x01\x02\x03\x04");
        assert_eq!(parse(&image).expect("parse")[0].status, VerifyStatus::CantParse);
        // Wrong content type OID.
        let wrong_type = seq(&[der(tag::OID, oid::MD5), der(tag::CONTEXT_0, &seq(&[]))]);
        let image = sign(unsigned.clone(), false, &wrong_type);
        assert_eq!(parse(&image).expect("parse")[0].status, VerifyStatus::WrongPkcs7Type);
        // Truncated SignedData.
        let truncated = seq(&[der(tag::OID, oid::SIGNED_DATA), der(tag::CONTEXT_0, &seq(&[der(tag::INTEGER, &[1])]))]);
        let image = sign(unsigned.clone(), false, &truncated);
        assert_eq!(parse(&image).expect("parse")[0].status, VerifyStatus::CantParse);
        // SignedData whose content is not SpcIndirectData.
        let bad_content = seq(&[
            der(tag::OID, oid::SIGNED_DATA),
            der(
                tag::CONTEXT_0,
                &seq(&[
                    der(tag::INTEGER, &[1]),
                    set(&[]),
                    seq(&[der(tag::OID, oid::MD5)]),
                    set(&[]),
                ]),
            ),
        ]);
        let image = sign(unsigned.clone(), false, &bad_content);
        let sigs = parse(&image).expect("parse");
        assert_eq!(sigs[0].status, VerifyStatus::BadContent);
        assert_eq!(sigs[0].version, 1);
        // No SignerInfo (empty signerInfos SET).
        let no_signer = seq(&[
            der(tag::OID, oid::SIGNED_DATA),
            der(
                tag::CONTEXT_0,
                &seq(&[
                    der(tag::INTEGER, &[1]),
                    set(&[]),
                    spc_content(oid::SHA256, &expected),
                    set(&[]),
                ]),
            ),
        ]);
        let image = sign(unsigned.clone(), false, &no_signer);
        let sigs = parse(&image).expect("parse");
        assert_eq!(sigs[0].status, VerifyStatus::NoSignerInfo);
        assert_eq!(sigs[0].digest, expected);
        assert_eq!(sigs[0].digest_alg, "sha256");
        // Unknown digest algorithm: no file digest computed.
        let unknown = pkcs7(
            &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x63],
            &[1, 2, 3],
            Some(&[0; 32]),
            &[],
        );
        let image = sign(unsigned.clone(), false, &unknown);
        let sigs = parse(&image).expect("parse");
        assert_eq!(sigs[0].status, VerifyStatus::UnknownAlgorithm);
        assert_eq!(sigs[0].digest_alg, "1.3.6.1.4.1.311.99");
        assert!(sigs[0].file_digest.is_empty());
        // Known algorithm but empty digest: UnknownAlgorithm too.
        let empty = pkcs7(oid::SHA256, &[], Some(&[0; 32]), &[]);
        let image = sign(unsigned.clone(), false, &empty);
        assert_eq!(parse(&image).expect("parse")[0].status, VerifyStatus::UnknownAlgorithm);
        // Signer without the pkcs9 messageDigest attribute.
        let missing = pkcs7(oid::SHA256, &expected, None, &[]);
        let image = sign(unsigned, false, &missing);
        assert_eq!(parse(&image).expect("parse")[0].status, VerifyStatus::DigestMissing);
    }

    #[test]
    fn nested_signatures_are_parsed_first_and_verified_independently() {
        let unsigned = unsigned_pe(false, 0x1000);
        let sha256 = reference_digest(DigestAlgorithm::Sha256, &unsigned, false, unsigned.len());
        let sha1 = reference_digest(DigestAlgorithm::Sha1, &unsigned, false, unsigned.len());
        let inner = pkcs7(oid::SHA256, &sha256, Some(&[0x22; 32]), &[]);
        let outer = pkcs7(oid::SHA1, &sha1, Some(&[0x33; 20]), &[inner]);
        let image = sign(unsigned.clone(), false, &outer);
        let sigs = parse(&image).expect("parse");
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].depth, 1);
        assert_eq!(sigs[0].digest_alg, "sha256");
        assert_eq!(sigs[0].status, VerifyStatus::Valid);
        assert_eq!(sigs[0].file_digest, sha256);
        assert_eq!(sigs[1].depth, 0);
        assert_eq!(sigs[1].digest_alg, "sha1");
        assert_eq!(sigs[1].status, VerifyStatus::Valid);
        assert_eq!(sigs[1].file_digest, sha1);

        // A wrong nested digest does not affect the outer signature.
        let bad_inner = pkcs7(oid::SHA256, &[0xEE; 32], Some(&[0x22; 32]), &[]);
        let outer = pkcs7(oid::SHA1, &sha1, Some(&[0x33; 20]), &[bad_inner]);
        let image = sign(unsigned.clone(), false, &outer);
        let sigs = parse(&image).expect("parse");
        assert_eq!(sigs[0].status, VerifyStatus::WrongFileDigest);
        assert_eq!(sigs[1].status, VerifyStatus::Valid);

        // Nesting is bounded.
        let mut deep = pkcs7(oid::SHA256, &sha256, Some(&[0; 32]), &[]);
        for _ in 0..(MAX_NESTED_DEPTH + 4) {
            deep = pkcs7(oid::SHA256, &sha256, Some(&[0; 32]), &[deep]);
        }
        let image = sign(unsigned, false, &deep);
        let sigs = parse(&image).expect("parse");
        assert_eq!(sigs.len(), MAX_NESTED_DEPTH + 1);
        assert!(sigs.iter().all(|s| s.depth <= MAX_NESTED_DEPTH));
        assert!(sigs.iter().all(|s| s.status == VerifyStatus::Valid));
    }

    #[test]
    fn der_reader_is_bounded() {
        assert!(tlv(&[]).is_none());
        assert!(tlv(&[0x30]).is_none());
        assert!(tlv(&[0x30, 0x05, 0x01]).is_none(), "body shorter than length");
        assert!(tlv(&[0x30, 0x80]).is_none(), "indefinite length rejected");
        assert!(tlv(&[0x30, 0x85, 1, 1, 1, 1, 1]).is_none(), "length of length > 4 rejected");
        assert!(tlv(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]).is_none(), "huge length rejected");
        let long = der(0x04, &[7; 300]);
        let t = tlv(&long).expect("long form");
        assert_eq!(t.body.len(), 300);
        assert_eq!(t.raw.len(), long.len());
        assert_eq!(integer_u64(&[0x01, 0x00]), 256);
        assert_eq!(integer_u64(&[0xFF; 9]), u64::MAX);
        assert_eq!(integer_u64(&[]), 0);
        // A trailing truncated child ends the iteration.
        assert_eq!(children(&[0x02, 0x01, 0x05, 0x02, 0x01]).count(), 1);
        assert!(expect(&[0x02, 0x01, 0x05], tag::SEQUENCE).is_none());
        assert!(parse_spc_indirect_data(&seq(&[seq(&[])])).is_none());
        assert!(parse_signer_info(&[]).is_none());
    }

    #[test]
    fn oid_helpers() {
        assert_eq!(oid::to_dotted(oid::SHA256), "2.16.840.1.101.3.4.2.1");
        assert_eq!(oid::to_dotted(oid::SIGNED_DATA), "1.2.840.113549.1.7.2");
        assert_eq!(oid::to_dotted(oid::SPC_INDIRECT_DATA), "1.3.6.1.4.1.311.2.1.4");
        assert_eq!(oid::to_dotted(oid::SPC_NESTED_SIGNATURE), "1.3.6.1.4.1.311.2.4.1");
        assert_eq!(oid::to_dotted(oid::SPC_MS_COUNTERSIGNATURE), "1.3.6.1.4.1.311.3.3.1");
        assert_eq!(oid::to_dotted(oid::PKCS9_MESSAGE_DIGEST), "1.2.840.113549.1.9.4");
        assert_eq!(oid::to_dotted(oid::SHA1), "1.3.14.3.2.26");
        assert_eq!(oid::to_dotted(oid::MD5), "1.2.840.113549.2.5");
        assert_eq!(oid::to_dotted(&[0x88, 0x37]), "2.999");
        assert_eq!(oid::to_dotted(&[]), "");
        assert_eq!(
            oid::to_dotted(&[0x2B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x01]),
            "1.3.?.1"
        );
        for (alg, body) in [
            (DigestAlgorithm::Md5, oid::MD5),
            (DigestAlgorithm::Sha1, oid::SHA1),
            (DigestAlgorithm::Sha256, oid::SHA256),
            (DigestAlgorithm::Sha384, oid::SHA384),
            (DigestAlgorithm::Sha512, oid::SHA512),
        ] {
            assert_eq!(DigestAlgorithm::from_oid(body), Some(alg));
            assert_eq!(DigestAlgorithm::from_name(alg.name()), Some(alg));
            let md = MessageDigest {
                algorithm_oid: body.to_vec(),
                digest: vec![0; alg.size()],
            };
            assert_eq!(md.algorithm(), Some(alg));
            assert_eq!(md.algorithm_name(), alg.name());
        }
        assert_eq!(DigestAlgorithm::from_oid(&[1, 2, 3]), None);
        assert_eq!(DigestAlgorithm::from_name("sha3-256"), None);
        assert_eq!(VerifyStatus::WrongPkcs7Type.name(), "WrongPKCS7Type");
        assert_eq!(VerifyStatus::Valid.name(), "Valid");
        assert_eq!(VerifyStatus::Valid as u32, 0);
        assert_eq!(VerifyStatus::UnknownAlgorithm as u32, 10);
        assert_eq!(AuthenticodeError::NotMz.to_string(), "missing MZ signature");
        assert!(MAX_DIGEST_SIZE >= DigestAlgorithm::Sha512.size());
        assert_eq!(DIGEST_CHUNK_SIZE, 0xFFFF);
    }

    /// Runs the parser over signed Windows binaries when present; a
    /// machine without them passes trivially.
    #[test]
    fn real_signed_binaries_when_available() {
        let candidates = [
            r"C:\Windows\explorer.exe",
            r"C:\Windows\System32\ntoskrnl.exe",
            r"C:\Windows\System32\winload.exe",
            r"C:\Windows\System32\ci.dll",
        ];
        for path in candidates {
            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            let Ok(sigs) = parse(&bytes) else {
                continue;
            };
            assert!(!sigs.is_empty(), "{path}: no signatures");
            eprintln!("{path}: {:?}", sigs.iter().map(|s| (s.status, s.digest_alg.as_str())).collect::<Vec<_>>());
            assert!(
                sigs.iter().any(|s| s.status == VerifyStatus::Valid),
                "{path}: {:?}",
                sigs.iter().map(|s| (s.status, s.digest_alg.clone())).collect::<Vec<_>>()
            );
        }
    }
}
