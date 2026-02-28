//! Versioned share format: binary encoding, PEM envelope, encoding auto-detection.
//!
//! Binary format (V1):
//! ```text
//! [0x4B 'K'] [0x51 'Q'] [version: 1B] [flags: 1B] [optional CRC32: 4B] [sharks data]
//! ```
//!
//! PEM envelope (optional wrapper):
//! ```text
//! KEYQUORUM-SHARE-V1
//! Share: 1 of 5 (threshold 3)
//! Scheme: shamir-gf256
//! Integrity: crc32
//!
//! <base64 or base32 encoded payload>
//! ```

use base64::Engine;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Magic bytes identifying a versioned keyquorum share.
pub const MAGIC: [u8; 2] = [0x4B, 0x51]; // "KQ"

/// Current format version.
pub const VERSION_1: u8 = 0x01;

/// Flag bit: per-share CRC32 is present (4 bytes after flags byte).
pub const FLAG_CRC32: u8 = 0b0000_0001;

/// Reserved flag bits — reject if any are set (forward safety).
pub const FLAGS_RESERVED: u8 = 0b1111_1110;

/// PEM envelope marker line.
pub const ENVELOPE_MARKER: &str = "KEYQUORUM-SHARE-V1";

/// Encoding used for the share payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShareEncoding {
    #[default]
    Base64,
    Base32,
}

/// Options controlling share generation output format.
#[derive(Clone, Debug)]
pub struct ShareFormatOptions {
    /// Encoding for the payload.
    pub encoding: ShareEncoding,
    /// Whether to include per-share CRC32 in the binary payload.
    pub include_crc32: bool,
    /// Whether to include the PEM envelope.
    pub include_envelope: bool,
    /// Whether to include metadata headers in the envelope.
    pub include_metadata: bool,
    /// Share number (1-indexed) for envelope header.
    pub share_number: u8,
    /// Total shares for envelope header.
    pub total_shares: u8,
    /// Threshold for envelope header.
    pub threshold: u8,
}

/// Metadata extracted from a PEM envelope.
#[derive(Clone, Debug, Default)]
pub struct EnvelopeMetadata {
    /// Share number (1-indexed), e.g., 1 in "Share: 1 of 5 (threshold 3)"
    pub share_number: Option<u8>,
    /// Total shares, e.g., 5
    pub total_shares: Option<u8>,
    /// Threshold, e.g., 3
    pub threshold: Option<u8>,
    /// Scheme identifier, e.g., "shamir-gf256"
    pub scheme: Option<String>,
    /// Integrity method, e.g., "crc32" or "none"
    pub integrity: Option<String>,
}

/// Result of parsing a share from any supported format.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ParsedShare {
    /// Raw sharks share bytes (x-coordinate + y-values).
    pub sharks_data: Vec<u8>,
    /// Share x-coordinate (first byte of sharks_data).
    #[zeroize(skip)]
    pub index: u8,
    /// Format version: None for legacy, Some(1) for v1.
    #[zeroize(skip)]
    pub version: Option<u8>,
    /// Whether CRC32 was present and verified.
    #[zeroize(skip)]
    pub crc32_verified: bool,
    /// Envelope metadata (if PEM envelope was present).
    #[zeroize(skip)]
    pub metadata: Option<EnvelopeMetadata>,
    /// Whether the input was a PEM envelope.
    #[zeroize(skip)]
    pub had_envelope: bool,
    /// Whether the payload was extracted from a malformed/partial envelope.
    #[zeroize(skip)]
    pub malformed_envelope: bool,
}

#[derive(Debug, Error)]
pub enum ShareFormatError {
    #[error("unsupported share format version: {0}")]
    UnsupportedVersion(u8),
    #[error("unknown flags set: 0x{0:02x}")]
    UnknownFlags(u8),
    #[error("CRC32 mismatch: expected 0x{expected:08x}, got 0x{actual:08x}")]
    Crc32Mismatch { expected: u32, actual: u32 },
    #[error("share data too short: need at least {minimum} bytes, got {actual}")]
    TooShort { minimum: usize, actual: usize },
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
    #[error("invalid envelope format: {0}")]
    InvalidEnvelope(String),
    #[error("metadata mismatch: {0}")]
    MetadataMismatch(String),
    #[error("empty share data")]
    Empty,
}

// ---------------------------------------------------------------------------
// Binary format encoding/decoding
// ---------------------------------------------------------------------------

/// Encode raw sharks share bytes into the V1 binary format.
pub fn encode_v1(sharks_data: &[u8], include_crc32: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + if include_crc32 { 4 } else { 0 } + sharks_data.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION_1);

    let flags = if include_crc32 { FLAG_CRC32 } else { 0 };
    out.push(flags);

    if include_crc32 {
        let crc = crc32fast::hash(sharks_data);
        out.extend_from_slice(&crc.to_be_bytes());
    }

    out.extend_from_slice(sharks_data);
    out
}

/// Decode a binary payload, auto-detecting legacy vs V1 format.
pub fn decode_payload(bytes: &[u8]) -> Result<ParsedShare, ShareFormatError> {
    if bytes.is_empty() {
        return Err(ShareFormatError::Empty);
    }

    // Check for magic prefix
    if bytes.len() < 2 || bytes[0..2] != MAGIC {
        // Legacy format: entire input is raw sharks data
        return Ok(ParsedShare {
            index: bytes[0],
            sharks_data: bytes.to_vec(),
            version: None,
            crc32_verified: false,
            metadata: None,
            had_envelope: false,
            malformed_envelope: false,
        });
    }

    // V1 format: need at least magic(2) + version(1) + flags(1) + 1 byte sharks data
    if bytes.len() < 5 {
        return Err(ShareFormatError::TooShort {
            minimum: 5,
            actual: bytes.len(),
        });
    }

    let version = bytes[2];
    if version != VERSION_1 {
        return Err(ShareFormatError::UnsupportedVersion(version));
    }

    let flags = bytes[3];
    if flags & FLAGS_RESERVED != 0 {
        return Err(ShareFormatError::UnknownFlags(flags));
    }

    let has_crc32 = flags & FLAG_CRC32 != 0;
    let data_offset;
    let mut crc32_verified = false;

    if has_crc32 {
        // Need at least header(4) + crc32(4) + 1 byte sharks data
        if bytes.len() < 9 {
            return Err(ShareFormatError::TooShort {
                minimum: 9,
                actual: bytes.len(),
            });
        }
        let expected_crc = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        data_offset = 8;
        let sharks_data = &bytes[data_offset..];
        let actual_crc = crc32fast::hash(sharks_data);
        if expected_crc != actual_crc {
            return Err(ShareFormatError::Crc32Mismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }
        crc32_verified = true;
    } else {
        data_offset = 4;
    }

    let sharks_data = bytes[data_offset..].to_vec();
    if sharks_data.is_empty() {
        return Err(ShareFormatError::TooShort {
            minimum: data_offset + 1,
            actual: bytes.len(),
        });
    }

    Ok(ParsedShare {
        index: sharks_data[0],
        sharks_data,
        version: Some(VERSION_1),
        crc32_verified,
        metadata: None,
        had_envelope: false,
        malformed_envelope: false,
    })
}

// ---------------------------------------------------------------------------
// Byte encoding/decoding (base64/base32)
// ---------------------------------------------------------------------------

/// Encode bytes using the specified encoding.
pub fn encode_bytes(data: &[u8], encoding: ShareEncoding) -> String {
    match encoding {
        ShareEncoding::Base64 => {
            base64::engine::general_purpose::STANDARD.encode(data)
        }
        ShareEncoding::Base32 => {
            data_encoding::BASE32_NOPAD.encode(data)
        }
    }
}

/// Try decoding as base64. Returns None if invalid.
fn try_decode_base64(input: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(input).ok()
}

/// Try decoding as base32 (case-insensitive). Returns None if invalid.
fn try_decode_base32(input: &str) -> Option<Vec<u8>> {
    let upper = input.to_uppercase();
    data_encoding::BASE32_NOPAD.decode(upper.as_bytes()).ok()
}

/// Decode a string using auto-detected encoding (try base64 first, then base32).
/// For simple cases where the caller doesn't need v1-aware disambiguation.
pub fn decode_bytes(input: &str) -> Result<Vec<u8>, ShareFormatError> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();

    if cleaned.is_empty() {
        return Err(ShareFormatError::Empty);
    }

    if let Some(bytes) = try_decode_base64(&cleaned) {
        return Ok(bytes);
    }

    if let Some(bytes) = try_decode_base32(&cleaned) {
        return Ok(bytes);
    }

    Err(ShareFormatError::InvalidEncoding(
        "data is not valid base64 or base32".to_string(),
    ))
}

/// Decode with v1-aware disambiguation: if both base64 and base32 decode
/// successfully, prefer whichever produces a valid v1 payload (KQ magic).
fn decode_bytes_smart(input: &str) -> Result<Vec<u8>, ShareFormatError> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();

    if cleaned.is_empty() {
        return Err(ShareFormatError::Empty);
    }

    let b64 = try_decode_base64(&cleaned);
    let b32 = try_decode_base32(&cleaned);

    match (b64, b32) {
        (Some(b64_bytes), Some(b32_bytes)) => {
            // Both valid — prefer whichever has KQ magic (v1 format)
            let b64_is_v1 = b64_bytes.len() >= 2 && b64_bytes[0..2] == MAGIC;
            let b32_is_v1 = b32_bytes.len() >= 2 && b32_bytes[0..2] == MAGIC;
            if b32_is_v1 && !b64_is_v1 {
                Ok(b32_bytes)
            } else {
                Ok(b64_bytes) // default: prefer base64
            }
        }
        (Some(bytes), None) => Ok(bytes),
        (None, Some(bytes)) => Ok(bytes),
        (None, None) => Err(ShareFormatError::InvalidEncoding(
            "data is not valid base64 or base32".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Envelope formatting/parsing
// ---------------------------------------------------------------------------

/// Format a share into its final string representation.
pub fn format_share(sharks_data: &[u8], opts: &ShareFormatOptions) -> String {
    let binary = encode_v1(sharks_data, opts.include_crc32);
    let encoded = encode_bytes(&binary, opts.encoding);

    if !opts.include_envelope {
        return encoded;
    }

    let mut lines = Vec::new();
    lines.push(ENVELOPE_MARKER.to_string());

    if opts.include_metadata {
        lines.push(format!(
            "Share: {} of {} (threshold {})",
            opts.share_number, opts.total_shares, opts.threshold
        ));
        lines.push("Scheme: shamir-gf256".to_string());
        lines.push(format!(
            "Integrity: {}",
            if opts.include_crc32 { "crc32" } else { "none" }
        ));
    }

    lines.push(String::new()); // blank separator
    lines.push(encoded);

    lines.join("\n")
}

/// Parse a share from any supported string format.
/// Auto-detects: PEM envelope, bare V1 payload, legacy raw sharks (base64/base32).
pub fn parse_share(input: &str) -> Result<ParsedShare, ShareFormatError> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err(ShareFormatError::Empty);
    }

    // Check for PEM envelope (possibly with leading junk like "Share 3 (index 5):" label)
    if trimmed.starts_with(ENVELOPE_MARKER) {
        return parse_envelope(trimmed);
    }
    if let Some(pos) = trimmed.find(ENVELOPE_MARKER) {
        return parse_envelope(trimmed[pos..].trim());
    }

    // Bare format: smart decode (disambiguates base64 vs base32 using KQ magic)
    match decode_bytes_smart(trimmed) {
        Ok(bytes) => decode_payload(&bytes),
        Err(bare_err) => {
            // Fallback: if input looks like a mangled envelope (has header-like lines),
            // try to extract just the payload lines
            if let Some(parsed) = try_extract_payload(trimmed) {
                Ok(parsed)
            } else {
                Err(bare_err)
            }
        }
    }
}

/// Try to extract a share payload from input that has orphaned envelope headers
/// (marker or header lines deleted). Returns None if no payload found.
fn try_extract_payload(input: &str) -> Option<ParsedShare> {
    let has_headers = input
        .lines()
        .any(|l| {
            let t = l.trim();
            matches!(t.split_once(':'), Some((k, _)) if
                matches!(k.trim(), "Share" | "Scheme" | "Integrity"))
        });

    if !has_headers {
        return None;
    }

    // Extract non-header, non-blank lines as candidate payload
    let payload: Vec<&str> = input
        .lines()
        .map(|l| l.trim())
        .filter(|l| {
            if l.is_empty() {
                return false;
            }
            // Skip lines that look like envelope headers
            if let Some((key, _)) = l.split_once(':') {
                if matches!(key.trim(), "Share" | "Scheme" | "Integrity") {
                    return false;
                }
            }
            true
        })
        .collect();

    if payload.is_empty() {
        return None;
    }

    let joined = payload.join("");
    let bytes = decode_bytes_smart(&joined).ok()?;
    let mut parsed = decode_payload(&bytes).ok()?;
    parsed.malformed_envelope = true;
    Some(parsed)
}

/// Parse a PEM envelope.
fn parse_envelope(input: &str) -> Result<ParsedShare, ShareFormatError> {
    let mut lines = input.lines();

    // First line must be the marker
    let first = lines.next().ok_or_else(|| {
        ShareFormatError::InvalidEnvelope("empty input".to_string())
    })?;
    if first.trim() != ENVELOPE_MARKER {
        return Err(ShareFormatError::InvalidEnvelope(format!(
            "expected '{}', got '{}'",
            ENVELOPE_MARKER, first
        )));
    }

    // Parse headers until blank line
    let mut metadata = EnvelopeMetadata::default();
    let mut has_any_metadata = false;
    let mut payload_lines = Vec::new();
    let mut found_separator = false;

    for line in lines {
        if !found_separator {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                found_separator = true;
                continue;
            }
            // Parse header
            if let Some((key, value)) = trimmed.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "Share" => {
                        if let Some(m) = parse_share_header(value) {
                            metadata.share_number = Some(m.0);
                            metadata.total_shares = Some(m.1);
                            metadata.threshold = Some(m.2);
                            has_any_metadata = true;
                        }
                    }
                    "Scheme" => {
                        metadata.scheme = Some(value.to_string());
                        has_any_metadata = true;
                    }
                    "Integrity" => {
                        metadata.integrity = Some(value.to_string());
                        has_any_metadata = true;
                    }
                    _ => {
                        // Unknown header — ignore for forward compatibility
                    }
                }
            }
        } else {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                payload_lines.push(trimmed.to_string());
            }
        }
    }

    if !found_separator {
        return Err(ShareFormatError::InvalidEnvelope(
            "no blank line separator found between headers and payload".to_string(),
        ));
    }

    if payload_lines.is_empty() {
        return Err(ShareFormatError::InvalidEnvelope(
            "no payload data after headers".to_string(),
        ));
    }

    // Concatenate payload lines and decode
    let payload_str = payload_lines.join("");
    let bytes = decode_bytes_smart(&payload_str)?;
    let mut parsed = decode_payload(&bytes)?;

    parsed.had_envelope = true;
    if has_any_metadata {
        parsed.metadata = Some(metadata);
    }

    Ok(parsed)
}

/// Parse "N of M (threshold K)" format from Share header value.
fn parse_share_header(value: &str) -> Option<(u8, u8, u8)> {
    // Format: "1 of 5 (threshold 3)"
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    // parts: ["1", "of", "5", "(threshold", "3)"]
    let share_num: u8 = parts[0].parse().ok()?;
    if parts[1] != "of" {
        return None;
    }
    let total: u8 = parts[2].parse().ok()?;
    if !parts[3].starts_with("(threshold") {
        return None;
    }
    let threshold_str = parts[4].trim_end_matches(')');
    let threshold: u8 = threshold_str.parse().ok()?;
    Some((share_num, total, threshold))
}

/// Validate envelope metadata against daemon config.
pub fn validate_metadata(
    meta: &EnvelopeMetadata,
    threshold: u8,
    total_shares: u8,
) -> Result<(), ShareFormatError> {
    if let Some(t) = meta.threshold {
        if t != threshold {
            return Err(ShareFormatError::MetadataMismatch(format!(
                "share threshold is {} but daemon expects {}",
                t, threshold
            )));
        }
    }
    if let Some(n) = meta.total_shares {
        if n != total_shares {
            return Err(ShareFormatError::MetadataMismatch(format!(
                "share total is {} but daemon expects {}",
                n, total_shares
            )));
        }
    }
    if let Some(ref scheme) = meta.scheme {
        if scheme != "shamir-gf256" {
            return Err(ShareFormatError::MetadataMismatch(format!(
                "unknown scheme '{}', expected 'shamir-gf256'",
                scheme
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: fake sharks data (x-coordinate + some y-values)
    fn sample_sharks_data() -> Vec<u8> {
        vec![42, 10, 20, 30, 40, 50, 60, 70, 80]
    }

    // -- Binary encoding/decoding --

    #[test]
    fn encode_v1_without_crc32() {
        let data = sample_sharks_data();
        let encoded = encode_v1(&data, false);
        assert_eq!(encoded[0], 0x4B); // K
        assert_eq!(encoded[1], 0x51); // Q
        assert_eq!(encoded[2], VERSION_1);
        assert_eq!(encoded[3], 0x00); // no flags
        assert_eq!(&encoded[4..], &data);
    }

    #[test]
    fn encode_v1_with_crc32() {
        let data = sample_sharks_data();
        let encoded = encode_v1(&data, true);
        assert_eq!(encoded[0], 0x4B);
        assert_eq!(encoded[1], 0x51);
        assert_eq!(encoded[2], VERSION_1);
        assert_eq!(encoded[3], FLAG_CRC32);
        let crc_bytes = &encoded[4..8];
        let expected_crc = crc32fast::hash(&data);
        assert_eq!(crc_bytes, &expected_crc.to_be_bytes());
        assert_eq!(&encoded[8..], &data);
    }

    #[test]
    fn encode_v1_roundtrip() {
        let data = sample_sharks_data();
        let encoded = encode_v1(&data, true);
        let parsed = decode_payload(&encoded).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert_eq!(parsed.index, 42);
        assert_eq!(parsed.version, Some(VERSION_1));
        assert!(parsed.crc32_verified);
    }

    #[test]
    fn encode_v1_roundtrip_no_crc() {
        let data = sample_sharks_data();
        let encoded = encode_v1(&data, false);
        let parsed = decode_payload(&encoded).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert_eq!(parsed.version, Some(VERSION_1));
        assert!(!parsed.crc32_verified);
    }

    #[test]
    fn decode_payload_legacy() {
        let data = sample_sharks_data();
        let parsed = decode_payload(&data).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert_eq!(parsed.index, 42);
        assert!(parsed.version.is_none());
        assert!(!parsed.crc32_verified);
    }

    #[test]
    fn decode_payload_crc32_mismatch() {
        let data = sample_sharks_data();
        let mut encoded = encode_v1(&data, true);
        // Tamper with one byte of sharks data
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;
        let err = decode_payload(&encoded).unwrap_err();
        assert!(matches!(err, ShareFormatError::Crc32Mismatch { .. }));
    }

    #[test]
    fn decode_payload_unknown_version() {
        let mut bytes = vec![0x4B, 0x51, 0x02, 0x00, 42];
        let err = decode_payload(&bytes).unwrap_err();
        assert!(matches!(err, ShareFormatError::UnsupportedVersion(0x02)));
        // Also test version 0
        bytes[2] = 0x00;
        let err = decode_payload(&bytes).unwrap_err();
        assert!(matches!(err, ShareFormatError::UnsupportedVersion(0x00)));
    }

    #[test]
    fn decode_payload_reserved_flags() {
        let bytes = vec![0x4B, 0x51, 0x01, 0x02, 42]; // flag bit 1 set
        let err = decode_payload(&bytes).unwrap_err();
        assert!(matches!(err, ShareFormatError::UnknownFlags(0x02)));
    }

    #[test]
    fn decode_payload_too_short() {
        // Just magic + version, no flags or data
        let bytes = vec![0x4B, 0x51, 0x01];
        let err = decode_payload(&bytes).unwrap_err();
        assert!(matches!(err, ShareFormatError::TooShort { .. }));

        // Header complete but no sharks data
        let bytes = vec![0x4B, 0x51, 0x01, 0x00];
        let err = decode_payload(&bytes).unwrap_err();
        assert!(matches!(err, ShareFormatError::TooShort { .. }));

        // CRC32 flag set but not enough bytes for CRC + data
        let bytes = vec![0x4B, 0x51, 0x01, 0x01, 0x00, 0x00];
        let err = decode_payload(&bytes).unwrap_err();
        assert!(matches!(err, ShareFormatError::TooShort { .. }));
    }

    #[test]
    fn decode_payload_empty() {
        let err = decode_payload(&[]).unwrap_err();
        assert!(matches!(err, ShareFormatError::Empty));
    }

    // -- Byte encoding/decoding --

    #[test]
    fn encode_decode_bytes_base64() {
        let data = sample_sharks_data();
        let encoded = encode_bytes(&data, ShareEncoding::Base64);
        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_decode_bytes_base32() {
        let data = sample_sharks_data();
        let encoded = encode_bytes(&data, ShareEncoding::Base32);
        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_bytes_base32_case_insensitive() {
        let data = sample_sharks_data();
        let encoded = encode_bytes(&data, ShareEncoding::Base32);
        // Try lowercase
        let decoded = decode_bytes(&encoded.to_lowercase()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_bytes_with_whitespace() {
        let data = sample_sharks_data();
        let encoded = encode_bytes(&data, ShareEncoding::Base64);
        // Add whitespace
        let with_spaces = format!("  {} \n ", encoded);
        let decoded = decode_bytes(&with_spaces).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_bytes_invalid() {
        let err = decode_bytes("!!!not-valid-anything!!!").unwrap_err();
        assert!(matches!(err, ShareFormatError::InvalidEncoding(_)));
    }

    #[test]
    fn decode_bytes_empty() {
        let err = decode_bytes("").unwrap_err();
        assert!(matches!(err, ShareFormatError::Empty));
    }

    // -- Full format_share / parse_share --

    #[test]
    fn format_share_bare_base64() {
        let data = sample_sharks_data();
        let opts = ShareFormatOptions {
            encoding: ShareEncoding::Base64,
            include_crc32: true,
            include_envelope: false,
            include_metadata: false,
            share_number: 1,
            total_shares: 5,
            threshold: 3,
        };
        let formatted = format_share(&data, &opts);
        // Should be a single line of base64
        assert!(!formatted.contains('\n'));
        // Should roundtrip
        let parsed = parse_share(&formatted).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert_eq!(parsed.version, Some(VERSION_1));
        assert!(parsed.crc32_verified);
        assert!(!parsed.had_envelope);
    }

    #[test]
    fn format_share_bare_base32() {
        let data = sample_sharks_data();
        let opts = ShareFormatOptions {
            encoding: ShareEncoding::Base32,
            include_crc32: false,
            include_envelope: false,
            include_metadata: false,
            share_number: 1,
            total_shares: 3,
            threshold: 2,
        };
        let formatted = format_share(&data, &opts);
        assert!(!formatted.contains('\n'));
        let parsed = parse_share(&formatted).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert!(!parsed.crc32_verified);
    }

    #[test]
    fn format_share_envelope_full() {
        let data = sample_sharks_data();
        let opts = ShareFormatOptions {
            encoding: ShareEncoding::Base64,
            include_crc32: true,
            include_envelope: true,
            include_metadata: true,
            share_number: 2,
            total_shares: 5,
            threshold: 3,
        };
        let formatted = format_share(&data, &opts);
        assert!(formatted.starts_with(ENVELOPE_MARKER));
        assert!(formatted.contains("Share: 2 of 5 (threshold 3)"));
        assert!(formatted.contains("Scheme: shamir-gf256"));
        assert!(formatted.contains("Integrity: crc32"));

        let parsed = parse_share(&formatted).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert!(parsed.had_envelope);
        assert!(parsed.crc32_verified);
        let meta = parsed.metadata.clone().unwrap();
        assert_eq!(meta.share_number, Some(2));
        assert_eq!(meta.total_shares, Some(5));
        assert_eq!(meta.threshold, Some(3));
        assert_eq!(meta.scheme.as_deref(), Some("shamir-gf256"));
        assert_eq!(meta.integrity.as_deref(), Some("crc32"));
    }

    #[test]
    fn format_share_envelope_no_metadata() {
        let data = sample_sharks_data();
        let opts = ShareFormatOptions {
            encoding: ShareEncoding::Base64,
            include_crc32: true,
            include_envelope: true,
            include_metadata: false,
            share_number: 1,
            total_shares: 3,
            threshold: 2,
        };
        let formatted = format_share(&data, &opts);
        assert!(formatted.starts_with(ENVELOPE_MARKER));
        assert!(!formatted.contains("Share:"));
        assert!(!formatted.contains("Scheme:"));

        let parsed = parse_share(&formatted).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert!(parsed.had_envelope);
        // No metadata headers -> metadata should be None
        assert!(parsed.metadata.is_none());
    }

    #[test]
    fn format_share_envelope_integrity_none() {
        let data = sample_sharks_data();
        let opts = ShareFormatOptions {
            encoding: ShareEncoding::Base64,
            include_crc32: false,
            include_envelope: true,
            include_metadata: true,
            share_number: 1,
            total_shares: 3,
            threshold: 2,
        };
        let formatted = format_share(&data, &opts);
        assert!(formatted.contains("Integrity: none"));
    }

    #[test]
    fn parse_share_legacy_base64() {
        // Raw sharks data encoded as base64 (no KQ prefix)
        let data = sample_sharks_data();
        let engine = base64::engine::general_purpose::STANDARD;
        let encoded = engine.encode(&data);

        let parsed = parse_share(&encoded).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert!(parsed.version.is_none()); // legacy
        assert!(!parsed.had_envelope);
    }

    #[test]
    fn parse_share_roundtrip_all_formats() {
        let data = sample_sharks_data();

        // Bare base64 with CRC
        let opts = ShareFormatOptions {
            encoding: ShareEncoding::Base64,
            include_crc32: true,
            include_envelope: false,
            include_metadata: false,
            share_number: 1,
            total_shares: 5,
            threshold: 3,
        };
        let s = format_share(&data, &opts);
        assert_eq!(parse_share(&s).unwrap().sharks_data, data);

        // Bare base32 without CRC
        let opts2 = ShareFormatOptions {
            encoding: ShareEncoding::Base32,
            include_crc32: false,
            include_envelope: false,
            include_metadata: false,
            share_number: 1,
            total_shares: 3,
            threshold: 2,
        };
        let s = format_share(&data, &opts2);
        assert_eq!(parse_share(&s).unwrap().sharks_data, data);

        // Full envelope base64
        let opts3 = ShareFormatOptions {
            encoding: ShareEncoding::Base64,
            include_crc32: true,
            include_envelope: true,
            include_metadata: true,
            share_number: 3,
            total_shares: 5,
            threshold: 3,
        };
        let s = format_share(&data, &opts3);
        assert_eq!(parse_share(&s).unwrap().sharks_data, data);

        // Envelope base32, no metadata
        let opts4 = ShareFormatOptions {
            encoding: ShareEncoding::Base32,
            include_crc32: true,
            include_envelope: true,
            include_metadata: false,
            share_number: 1,
            total_shares: 3,
            threshold: 2,
        };
        let s = format_share(&data, &opts4);
        assert_eq!(parse_share(&s).unwrap().sharks_data, data);
    }

    #[test]
    fn parse_share_envelope_missing_separator() {
        let input = "KEYQUORUM-SHARE-V1\nShare: 1 of 3 (threshold 2)\nSOMEDATA";
        let err = parse_share(input).unwrap_err();
        assert!(matches!(err, ShareFormatError::InvalidEnvelope(_)));
    }

    #[test]
    fn parse_share_envelope_no_payload() {
        let input = "KEYQUORUM-SHARE-V1\nShare: 1 of 3 (threshold 2)\n\n";
        let err = parse_share(input).unwrap_err();
        assert!(matches!(err, ShareFormatError::InvalidEnvelope(_)));
    }

    #[test]
    fn parse_share_envelope_unknown_headers_ignored() {
        let data = sample_sharks_data();
        let binary = encode_v1(&data, false);
        let encoded = encode_bytes(&binary, ShareEncoding::Base64);
        let input = format!(
            "KEYQUORUM-SHARE-V1\nFuture-Header: some-value\nShare: 1 of 3 (threshold 2)\n\n{}",
            encoded
        );
        let parsed = parse_share(&input).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert!(parsed.had_envelope);
        let meta = parsed.metadata.clone().unwrap();
        assert_eq!(meta.share_number, Some(1));
    }

    // -- Metadata validation --

    #[test]
    fn validate_metadata_matching() {
        let meta = EnvelopeMetadata {
            share_number: Some(1),
            total_shares: Some(5),
            threshold: Some(3),
            scheme: Some("shamir-gf256".to_string()),
            integrity: Some("crc32".to_string()),
        };
        validate_metadata(&meta, 3, 5).unwrap();
    }

    #[test]
    fn validate_metadata_threshold_mismatch() {
        let meta = EnvelopeMetadata {
            threshold: Some(3),
            ..Default::default()
        };
        let err = validate_metadata(&meta, 4, 5).unwrap_err();
        assert!(matches!(err, ShareFormatError::MetadataMismatch(_)));
    }

    #[test]
    fn validate_metadata_total_mismatch() {
        let meta = EnvelopeMetadata {
            total_shares: Some(5),
            ..Default::default()
        };
        let err = validate_metadata(&meta, 3, 7).unwrap_err();
        assert!(matches!(err, ShareFormatError::MetadataMismatch(_)));
    }

    #[test]
    fn validate_metadata_unknown_scheme() {
        let meta = EnvelopeMetadata {
            scheme: Some("aes-gcm".to_string()),
            ..Default::default()
        };
        let err = validate_metadata(&meta, 3, 5).unwrap_err();
        assert!(matches!(err, ShareFormatError::MetadataMismatch(_)));
    }

    #[test]
    fn validate_metadata_partial_ok() {
        // Only some fields present — should validate only those
        let meta = EnvelopeMetadata {
            threshold: Some(3),
            ..Default::default()
        };
        validate_metadata(&meta, 3, 5).unwrap();
    }

    #[test]
    fn validate_metadata_empty_ok() {
        let meta = EnvelopeMetadata::default();
        validate_metadata(&meta, 3, 5).unwrap();
    }

    // -- Share header parsing --

    #[test]
    fn parse_share_header_valid() {
        let result = parse_share_header("1 of 5 (threshold 3)");
        assert_eq!(result, Some((1, 5, 3)));
    }

    #[test]
    fn parse_share_header_invalid() {
        assert!(parse_share_header("garbage").is_none());
        assert!(parse_share_header("1 of 5").is_none());
        assert!(parse_share_header("").is_none());
    }

    // -- CRLF handling --

    #[test]
    fn parse_share_envelope_crlf() {
        let data = sample_sharks_data();
        let binary = encode_v1(&data, true);
        let encoded = encode_bytes(&binary, ShareEncoding::Base64);
        // Build envelope with \r\n line endings
        let input = format!(
            "KEYQUORUM-SHARE-V1\r\nShare: 1 of 3 (threshold 2)\r\nScheme: shamir-gf256\r\nIntegrity: crc32\r\n\r\n{}",
            encoded
        );
        let parsed = parse_share(&input).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert!(parsed.had_envelope);
        assert!(parsed.crc32_verified);
        let meta = parsed.metadata.clone().unwrap();
        assert_eq!(meta.threshold, Some(2));
    }

    #[test]
    fn parse_share_envelope_with_label_prefix() {
        // User pastes the split stderr label along with the share
        let data = sample_sharks_data();
        let opts = ShareFormatOptions {
            encoding: ShareEncoding::Base64,
            include_crc32: true,
            include_envelope: true,
            include_metadata: true,
            share_number: 3,
            total_shares: 5,
            threshold: 2,
        };
        let formatted = format_share(&data, &opts);
        // Prepend the label that keyquorum-split writes to stderr
        let with_label = format!("Share 3 (index 42):\n{}", formatted);
        let parsed = parse_share(&with_label).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert!(parsed.had_envelope);
        assert!(parsed.crc32_verified);
    }

    #[test]
    fn parse_share_bare_with_leading_junk_no_envelope() {
        // Leading junk without an envelope marker should NOT be silently accepted
        let data = sample_sharks_data();
        let binary = encode_v1(&data, true);
        let encoded = encode_bytes(&binary, ShareEncoding::Base64);
        let with_junk = format!("some garbage\n{}", encoded);
        // This should fail because the junk isn't a valid envelope and the
        // whole string isn't valid base64
        assert!(parse_share(&with_junk).is_err());
    }

    #[test]
    fn parse_share_mangled_envelope_missing_marker() {
        // Envelope with marker and Share header deleted (common copy-paste error)
        let data = sample_sharks_data();
        let binary = encode_v1(&data, true);
        let encoded = encode_bytes(&binary, ShareEncoding::Base64);
        let mangled = format!("Scheme: shamir-gf256\nIntegrity: crc32\n\n{}", encoded);
        let parsed = parse_share(&mangled).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert!(parsed.malformed_envelope);
        assert!(!parsed.had_envelope);
        assert!(parsed.metadata.is_none());
    }

    #[test]
    fn parse_share_mangled_envelope_only_payload_and_headers() {
        // Just Integrity header + payload, no marker, no blank separator
        let data = sample_sharks_data();
        let binary = encode_v1(&data, true);
        let encoded = encode_bytes(&binary, ShareEncoding::Base64);
        let mangled = format!("Integrity: crc32\n{}", encoded);
        let parsed = parse_share(&mangled).unwrap();
        assert_eq!(parsed.sharks_data, data);
        assert!(parsed.malformed_envelope);
    }
}
