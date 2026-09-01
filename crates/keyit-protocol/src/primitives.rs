//! Value types for cryptographic and time-related record fields.
//!
//! Protocol records use dedicated newtypes for signatures, hashes,
//! public keys, nonces, and timestamps instead of raw `Vec<u8>` or
//! `String` fields. [`HashBytes`] is SHA-256 output,
//! [`SignatureBytes`] and [`SigningPublicKeyBytes`] are Ed25519 values,
//! and [`PublicKeyBytes`] is a fixed 32-byte X25519 public key wrapper.
//! [`NonceBytes`] remains variable-length because protocol records use
//! it for multiple nonce families; concrete AEAD nonce lengths are
//! enforced by [`crate::encryption`].
//!
//! None of the types in this module perform cryptographic operations
//! themselves — construction validates only byte length, never
//! cryptographic validity (e.g. "is this 32-byte string an actual
//! Ed25519 curve point"). [`crate::signing`] is what actually signs and
//! verifies.

use std::fmt;

use crate::error::ProtocolError;

/// Raw bytes of an Ed25519 signature.
///
/// Keyit signs with Ed25519, whose signatures are always exactly 64
/// bytes — the raw `(R, s)`
/// encoding, with no versioned wrapper. This type enforces that fixed
/// size; [`crate::signing`] is what actually produces and checks
/// signatures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignatureBytes([u8; 64]);

impl SignatureBytes {
    /// Validates and wraps raw signature bytes.
    ///
    /// The only check performed here is length: a 64-byte value is
    /// accepted regardless of whether it is a signature that would ever
    /// verify against anything. Cryptographic validity (does this
    /// signature verify against some public key and message) is checked
    /// separately by [`crate::signing::verify`], not at construction.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let array: [u8; 64] = bytes
            .try_into()
            .map_err(|_| ProtocolError::InvalidSignature {
                reason: format!("expected 64 bytes, found {}", bytes.len()),
            })?;
        Ok(Self(array))
    }

    /// Wraps a raw 64-byte value without validation, for use in tests
    /// only.
    #[cfg(any(test, feature = "test-util"))]
    pub const fn new_unchecked_for_test(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw 64-byte signature.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the raw 64-byte signature as an owned array, for handing
    /// to `ed25519_dalek`. Crate-private: external callers only ever see
    /// signatures through [`Self::as_bytes`] or the [`crate::signing`]
    /// API, never as a raw dalek type.
    pub(crate) const fn as_array(&self) -> [u8; 64] {
        self.0
    }
}

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Same rationale as the other byte-carrying primitives: never
        // dump raw signature bytes into Debug output.
        f.debug_tuple("SignatureBytes")
            .field(&format_args!("{} bytes", self.0.len()))
            .finish()
    }
}

/// Raw bytes of an Ed25519 signing (verifying) public key.
///
/// This is separate from [`PublicKeyBytes`] because Ed25519 signing keys
/// and X25519 key-agreement keys have different purposes even though
/// both are 32 bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SigningPublicKeyBytes([u8; 32]);

impl SigningPublicKeyBytes {
    /// Validates and wraps raw signing public key bytes.
    ///
    /// As with [`SignatureBytes::from_bytes`], only the length is
    /// checked here; whether these 32 bytes decode to a valid Ed25519
    /// curve point is checked lazily by
    /// [`crate::signing::verify`]/[`crate::signing::SignedRecord`] at
    /// verification time, not here.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ProtocolError::InvalidPublicKey {
                reason: format!("expected 32 bytes, found {}", bytes.len()),
            })?;
        Ok(Self(array))
    }

    /// Wraps a raw 32-byte value without validation, for use in tests
    /// only.
    #[cfg(any(test, feature = "test-util"))]
    pub const fn new_unchecked_for_test(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw 32-byte public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the raw 32-byte public key as an owned array, for handing
    /// to `ed25519_dalek`. Crate-private for the same reason as
    /// [`SignatureBytes::as_array`].
    pub(crate) const fn as_array(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for SigningPublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SigningPublicKeyBytes")
            .field(&format_args!("{} bytes", self.0.len()))
            .finish()
    }
}

/// Raw bytes of a protocol hash value.
///
/// The protocol hash algorithm is SHA-256, so this type has a fixed
/// 32-byte representation and a production constructor,
/// [`HashBytes::from_sha256_digest`]. It still performs no hashing itself;
/// [`crate::canonical::canonical_hash`] is what actually runs SHA-256.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HashBytes([u8; 32]);

impl HashBytes {
    /// Wraps the raw output of a SHA-256 digest.
    ///
    /// This is the production constructor: every real `HashBytes` in this
    /// codebase is expected to originate from an actual SHA-256
    /// computation (see [`crate::canonical::canonical_hash`]), not from
    /// hand-written bytes.
    pub const fn from_sha256_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Wraps a raw 32-byte value without going through SHA-256, for use in
    /// tests only.
    ///
    /// Named `_for_test` to make clear this is not how production code
    /// builds a `HashBytes`: it skips the hash computation entirely, which
    /// is only acceptable when a test needs a specific, arbitrary-looking
    /// hash value (e.g. a placeholder parent-revision hash) rather than an
    /// actual digest of some input.
    #[cfg(any(test, feature = "test-util"))]
    pub const fn new_unchecked_for_test(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw 32-byte digest.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HashBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Same rationale as the other primitive types below: never dump
        // the raw digest bytes into Debug output, even though a hash is
        // not secret. A constant-shaped "32 bytes" keeps test failure
        // output and logs quiet instead of spamming 32 hex-ish numbers.
        f.debug_tuple("HashBytes")
            .field(&format_args!("{} bytes", self.0.len()))
            .finish()
    }
}

/// Raw bytes of an X25519 public key.
///
/// Ed25519 signing public keys have their own fixed-size type,
/// [`SigningPublicKeyBytes`]; this type represents only X25519
/// key-agreement public keys. X25519 public
/// keys are 32 raw Montgomery u-coordinate bytes; construction checks
/// that length but, by design, does not reject low-order points here.
/// Real key agreement happens in [`crate::encryption`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyBytes([u8; 32]);

impl PublicKeyBytes {
    /// Validates and wraps raw X25519 public key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ProtocolError::InvalidPublicKey {
                reason: format!("expected 32 bytes, found {}", bytes.len()),
            })?;
        Ok(Self(array))
    }

    /// Wraps a raw 32-byte value without validation, for use in tests
    /// only.
    #[cfg(any(test, feature = "test-util"))]
    pub const fn new_unchecked_for_test(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw 32-byte public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the raw 32-byte public key as an owned array for handing
    /// to `x25519-dalek`.
    pub(crate) const fn as_array(&self) -> [u8; 32] {
        self.0
    }

    /// Number of bytes carried.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this value carries zero bytes. Always false for a valid
    /// fixed-size X25519 public key; retained for symmetry with older
    /// callers and tests.
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKeyBytes")
            .field(&format_args!("{} bytes", self.0.len()))
            .finish()
    }
}

/// Raw bytes of a not-yet-specified random nonce encoding.
///
/// Used for the project genesis nonce that makes `kvp_...` identifiers
/// globally unique. Distinct from [`HashBytes`] because a nonce is
/// random input, not a digest output.
#[derive(Clone, PartialEq, Eq)]
pub struct NonceBytes(Vec<u8>);

macro_rules! opaque_bytes {
    ($name:ident) => {
        impl $name {
            /// Wraps raw bytes without validation.
            ///
            /// Named `_for_test` to make it clear this is not a
            /// production constructor.
            #[cfg(any(test, feature = "test-util"))]
            pub fn new_unchecked_for_test(bytes: impl Into<Vec<u8>>) -> Self {
                Self(bytes.into())
            }

            /// Borrows the raw bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Number of bytes carried.
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// Whether this value carries zero bytes.
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Deliberately does not print the bytes themselves: even
                // though none of these types hold private key material,
                // getting into the habit of not dumping raw protocol
                // byte strings in Debug output costs nothing here and
                // avoids noisy test failure output.
                f.debug_tuple(stringify!($name))
                    .field(&format_args!("{} bytes", self.0.len()))
                    .finish()
            }
        }
    };
}

opaque_bytes!(NonceBytes);

impl NonceBytes {
    /// Wraps already-known nonce bytes.
    ///
    /// This is `NonceBytes`'s production constructor: a nonce's only
    /// requirement is that it came from a high-entropy source, and this
    /// type does not freeze one shared nonce length for every protocol
    /// use. Callers are expected to have generated `bytes` themselves
    /// from a CSPRNG or to be reconstructing a previously-generated
    /// nonce from storage; this constructor does not generate randomness
    /// itself.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

/// A whole-seconds Unix timestamp used across protocol records.
///
/// The protocol stores timestamps as whole Unix seconds. Human display
/// formatting belongs at the CLI/API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Builds a timestamp from whole seconds since the Unix epoch.
    pub const fn from_unix_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the whole seconds since the Unix epoch.
    pub const fn unix_seconds(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_bytes_from_bytes_accepts_64_bytes() {
        let sig = SignatureBytes::from_bytes(&[0u8; 64]).expect("64 bytes should be accepted");
        assert_eq!(sig.as_bytes().len(), 64);
    }

    #[test]
    fn signature_bytes_from_bytes_rejects_wrong_length() {
        let err = SignatureBytes::from_bytes(&[0u8; 63]).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidSignature { .. }));
    }

    #[test]
    fn signature_bytes_debug_does_not_leak_bytes() {
        let sig = SignatureBytes::new_unchecked_for_test([0xCDu8; 64]);
        let debug = format!("{sig:?}");
        assert!(debug.contains("64 bytes"));
        assert!(!debug.contains("205")); // 0xCD as decimal
    }

    #[test]
    fn signing_public_key_bytes_from_bytes_accepts_32_bytes() {
        let key =
            SigningPublicKeyBytes::from_bytes(&[0u8; 32]).expect("32 bytes should be accepted");
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn signing_public_key_bytes_from_bytes_rejects_wrong_length() {
        let err = SigningPublicKeyBytes::from_bytes(&[0u8; 31]).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidPublicKey { .. }));
    }

    #[test]
    fn signing_public_key_bytes_debug_does_not_leak_bytes() {
        let key = SigningPublicKeyBytes::new_unchecked_for_test([0xEFu8; 32]);
        let debug = format!("{key:?}");
        assert!(debug.contains("32 bytes"));
        assert!(!debug.contains("239")); // 0xEF as decimal
    }

    #[test]
    fn hash_bytes_debug_does_not_leak_digest() {
        let hash = HashBytes::new_unchecked_for_test([0xAB; 32]);
        let debug = format!("{hash:?}");
        assert!(debug.contains("32 bytes"));
        assert!(!debug.contains("171"));
        assert!(!debug.contains("AB"));
        assert!(!debug.contains("ab"));
    }

    #[test]
    fn hash_bytes_from_sha256_digest_round_trips_bytes() {
        let digest = [9u8; 32];
        let hash = HashBytes::from_sha256_digest(digest);
        assert_eq!(hash.as_bytes(), digest);
    }

    #[test]
    fn empty_bytes_report_is_empty() {
        let nonce = NonceBytes::new_unchecked_for_test(Vec::new());
        assert!(nonce.is_empty());
        assert_eq!(nonce.len(), 0);
    }

    #[test]
    fn public_key_bytes_from_bytes_accepts_32_bytes() {
        let key = PublicKeyBytes::from_bytes(&[5u8; 32]).expect("32 bytes should be accepted");
        assert_eq!(key.as_bytes(), [5u8; 32]);
    }

    #[test]
    fn public_key_bytes_from_bytes_rejects_wrong_length() {
        let err = PublicKeyBytes::from_bytes(&[5u8; 31]).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidPublicKey { .. }));
    }

    #[test]
    fn nonce_bytes_carry_arbitrary_length() {
        let nonce = NonceBytes::new_unchecked_for_test(vec![7u8; 16]);
        assert_eq!(nonce.len(), 16);
    }

    #[test]
    fn nonce_bytes_from_bytes_is_a_real_production_constructor() {
        // Unlike `new_unchecked_for_test`, `from_bytes` is not
        // `#[cfg(test)]`-gated; this test only confirms it round-trips
        // bytes the same way.
        let nonce = NonceBytes::from_bytes(vec![3u8; 12]);
        assert_eq!(nonce.as_bytes(), [3u8; 12]);
    }

    #[test]
    fn timestamp_round_trips_seconds() {
        let ts = Timestamp::from_unix_seconds(1_755_878_400);
        assert_eq!(ts.unix_seconds(), 1_755_878_400);
    }

    #[test]
    fn timestamps_are_orderable() {
        let earlier = Timestamp::from_unix_seconds(100);
        let later = Timestamp::from_unix_seconds(200);
        assert!(earlier < later);
    }
}
