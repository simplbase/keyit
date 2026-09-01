//! The protocol crate's error type.
//!
//! Kept as a single flat enum rather than a per-module error hierarchy or
//! an error-handling framework (e.g. `thiserror`, `anyhow`) so tests and
//! callers can match on precise protocol failures without an extra
//! dependency.

use std::fmt;

/// Errors produced by the Keyit protocol core.
///
/// This type deliberately stays small and specific to what the crate
/// actually validates: identifier shape, record well-formedness, public
/// key/signature byte shape, Ed25519 verification outcomes, and
/// encryption envelope shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The identifier did not start with the expected namespace prefix
    /// (for example, a `ProjectId` parsed from a string that did not
    /// start with `kvp_`).
    InvalidNamespace {
        /// Human-readable name of the identifier namespace, e.g.
        /// `"project"`.
        namespace: &'static str,
        /// The prefix that was expected, e.g. `"kvp_"`.
        expected_prefix: &'static str,
        /// The full string that was rejected.
        found: String,
    },
    /// The identifier had the correct namespace prefix, but the
    /// remainder of the identifier was malformed (empty, too short, or
    /// containing characters no candidate encoding would produce).
    InvalidIdentifier {
        /// Human-readable name of the identifier namespace, e.g.
        /// `"project"`.
        namespace: &'static str,
        /// Why the identifier body was rejected.
        reason: String,
    },
    /// A domain record was structurally malformed in a way that a typed
    /// constructor caught (for example, an empty required field).
    MalformedRecord {
        /// Name of the record type, e.g. `"ProjectGenesis"`.
        record: &'static str,
        /// Why the record was rejected.
        reason: String,
    },
    /// A protocol version string did not match any protocol version this
    /// build of Keyit understands.
    UnsupportedProtocolVersion(String),
    /// Raw bytes offered as a public key were malformed — currently only
    /// "wrong length"; curve-validity is checked lazily by the underlying
    /// Ed25519 implementation at verification time, not here at
    /// construction.
    InvalidPublicKey {
        /// Why the bytes were rejected.
        reason: String,
    },
    /// Raw bytes offered as private X25519 key material were malformed.
    InvalidPrivateKey {
        /// Why the bytes were rejected.
        reason: String,
    },
    /// Raw bytes offered as an environment data encryption key were
    /// malformed.
    InvalidSymmetricKey {
        /// Why the bytes were rejected.
        reason: String,
    },
    /// Raw bytes offered as an AEAD nonce were malformed.
    InvalidNonce {
        /// Why the bytes were rejected.
        reason: String,
    },
    /// Authenticated encryption failed while producing ciphertext.
    EncryptionFailed {
        /// Human-readable operation name.
        operation: &'static str,
    },
    /// Authenticated decryption failed. This covers wrong key, wrong
    /// nonce, wrong associated data, and corrupted ciphertext without
    /// distinguishing them.
    DecryptionFailed {
        /// Human-readable operation name.
        operation: &'static str,
    },
    /// Raw bytes offered as a signature were malformed (currently only
    /// "wrong length" — see [`ProtocolError::InvalidPublicKey`] for the
    /// same split between construction-time and verification-time
    /// checks).
    InvalidSignature {
        /// Why the bytes were rejected.
        reason: String,
    },
    /// A signature's raw bytes were well-formed, but did not verify
    /// against the given public key and canonical record preimage.
    ///
    /// This means only that the cryptographic check failed — it says
    /// nothing about whether the public key was authorized to sign the
    /// record.
    SignatureVerificationFailed {
        /// The signing domain-separation label of the record type being
        /// verified (e.g. `"keyit:v1:sign:revision"`), for diagnostics.
        label: String,
    },
    /// A `dotenv/v1` document could not be parsed or normalized.
    DotenvParse {
        /// 1-based line number where the parser detected the error.
        line: usize,
        /// Why the line was rejected.
        reason: String,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNamespace {
                namespace,
                expected_prefix,
                found,
            } => write!(
                f,
                "invalid {namespace} identifier: expected prefix \"{expected_prefix}\", found \"{found}\""
            ),
            Self::InvalidIdentifier { namespace, reason } => {
                write!(f, "invalid {namespace} identifier: {reason}")
            }
            Self::MalformedRecord { record, reason } => {
                write!(f, "malformed {record} record: {reason}")
            }
            Self::UnsupportedProtocolVersion(found) => {
                write!(f, "unsupported protocol version: \"{found}\"")
            }
            Self::InvalidPublicKey { reason } => {
                write!(f, "invalid public key: {reason}")
            }
            Self::InvalidPrivateKey { reason } => {
                write!(f, "invalid private key: {reason}")
            }
            Self::InvalidSymmetricKey { reason } => {
                write!(f, "invalid symmetric key: {reason}")
            }
            Self::InvalidNonce { reason } => {
                write!(f, "invalid nonce: {reason}")
            }
            Self::EncryptionFailed { operation } => {
                write!(f, "encryption failed while performing {operation}")
            }
            Self::DecryptionFailed { operation } => {
                write!(f, "decryption failed while performing {operation}")
            }
            Self::InvalidSignature { reason } => {
                write!(f, "invalid signature: {reason}")
            }
            Self::SignatureVerificationFailed { label } => {
                write!(f, "signature verification failed for \"{label}\"")
            }
            Self::DotenvParse { line, reason } => {
                write!(f, "invalid dotenv/v1 document at line {line}: {reason}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}
