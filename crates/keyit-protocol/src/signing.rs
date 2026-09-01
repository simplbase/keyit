//! Ed25519 signing and verification over canonical record preimages.
//!
//! This module is the only place in `keyit-protocol` that touches
//! `ed25519_dalek` directly. Everywhere else deals only in this crate's
//! own [`crate::primitives::SignatureBytes`] and
//! [`crate::primitives::SigningPublicKeyBytes`] newtypes; converting
//! those to and from `ed25519_dalek` types, and running the actual
//! cryptographic sign/verify operations, happens here and nowhere else.
//!
//! # What this module does not do
//!
//! - It does not store, persist, or serialize private key material —
//!   [`SigningKeyPair`] lives only in process memory for as long as a
//!   caller holds it.
//! - It does not implement OS keychain integration. Device key lifecycle
//!   is a `keyit-cli` concern.
//! - It does not decide whether a signer was *authorized* to sign a
//!   given record — [`SignedRecord::verify_signature_with`] and the
//!   per-record `verify_signature` methods check only the cryptographic
//!   signature. Membership/authorization checks are handled by higher
//!   layers.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroize;

use crate::canonical::{canonical_preimage, Canonicalize};
use crate::error::ProtocolError;
use crate::primitives::{SignatureBytes, SigningPublicKeyBytes};

/// An Ed25519 signing keypair, scoped strictly to signing/verification
/// operations.
///
/// This is explicitly **not** a device identity, an account, or
/// anything with a lifecycle beyond "exists in memory for as long as a
/// caller holds it" — `keyit-protocol`'s domain records
/// ([`crate::records`]) never embed a private key, only
/// [`crate::primitives::SigningPublicKeyBytes`]/
/// [`crate::primitives::SignatureBytes`].
pub struct SigningKeyPair(SigningKey);

impl std::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print private key material, even redacted-by-dalek's-own
        // Debug output — a hand-written impl here makes that guarantee
        // explicit and independent of `ed25519_dalek::SigningKey`'s own
        // `Debug` behavior, consistent with every other secret-adjacent
        // type in this crate.
        f.debug_tuple("SigningKeyPair")
            .field(&"Ed25519 signing keypair")
            .finish()
    }
}

impl SigningKeyPair {
    /// Generates a new random Ed25519 keypair using the operating
    /// system's CSPRNG via the `getrandom` crate.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("OS CSPRNG should be available");
        let keypair = Self(SigningKey::from_bytes(&secret));
        // `SigningKey::from_bytes` copies `secret` in rather than taking
        // ownership of the array, so the stack-local copy here still
        // holds live key material afterwards; zero it out. (The
        // `SigningKey` itself is zeroized on drop by `ed25519-dalek`'s
        // own `zeroize` integration, via its default `zeroize` feature —
        // this covers only this function's own transient buffer.)
        secret.zeroize();
        keypair
    }

    /// Reconstructs a keypair from a previously-generated 32-byte Ed25519
    /// signing seed.
    ///
    /// This is the counterpart to [`Self::to_bytes`]: it exists so a
    /// caller that has persisted a seed elsewhere can reload the same
    /// keypair on a later run instead of generating a fresh one every
    /// time. This module still does not persist anything itself.
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Returns this keypair's raw 32-byte Ed25519 signing seed.
    ///
    /// This **is** private key material. It exists so a caller can
    /// persist a generated keypair across process runs (paired with
    /// [`Self::from_bytes`]); this module itself never writes it to
    /// disk, and it is the caller's responsibility to store it safely
    /// (restrictive file permissions, never inside a project's
    /// `.keyit/`) and to
    /// zero any buffer holding it once it is no longer needed.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// This keypair's public verifying key, in Keyit's fixed-size byte
    /// form.
    pub fn public_key(&self) -> SigningPublicKeyBytes {
        SigningPublicKeyBytes::from_bytes(self.0.verifying_key().as_bytes())
            .expect("ed25519_dalek::VerifyingKey is always 32 bytes")
    }

    /// Signs `value`'s canonical encoding under `label`.
    ///
    /// This is the primitive [`SignedRecord`] implementations and tests
    /// build on.
    pub fn sign(&self, label: &str, value: &impl Canonicalize) -> SignatureBytes {
        let preimage = canonical_preimage(label, value);
        let signature = self.0.sign(&preimage);
        SignatureBytes::from_bytes(&signature.to_bytes())
            .expect("ed25519_dalek::Signature is always 64 bytes")
    }
}

/// Verifies that `signature` is a valid Ed25519 signature by
/// `public_key` over `value`'s canonical encoding under `label`.
///
/// Returns [`ProtocolError::InvalidPublicKey`] if `public_key`'s bytes
/// do not decode to a valid Ed25519 curve point, and
/// [`ProtocolError::SignatureVerificationFailed`] if the point and
/// signature are both well-formed but the signature does not verify.
/// Byte-length problems with either `public_key` or `signature` cannot
/// reach this function: both are validated at construction (see
/// [`crate::primitives::SigningPublicKeyBytes::from_bytes`] and
/// [`crate::primitives::SignatureBytes::from_bytes`]).
pub fn verify(
    label: &str,
    value: &impl Canonicalize,
    public_key: &SigningPublicKeyBytes,
    signature: &SignatureBytes,
) -> Result<(), ProtocolError> {
    let verifying_key = VerifyingKey::from_bytes(&public_key.as_array()).map_err(|e| {
        ProtocolError::InvalidPublicKey {
            reason: e.to_string(),
        }
    })?;
    let signature = Signature::from_bytes(&signature.as_array());

    let preimage = canonical_preimage(label, value);
    verifying_key
        .verify_strict(&preimage, &signature)
        .map_err(|_| ProtocolError::SignatureVerificationFailed {
            label: label.to_string(),
        })
}

/// A protocol record type whose canonical encoding carries an Ed25519
/// signature over the rest of its own fields.
///
/// This trait supplies the shared plumbing (the domain-separation
/// label, access to the signature field, and the actual verify call);
/// each signable record in [`crate::records`] also exposes its own
/// inherent `verify_signature` method (either no-argument, when the
/// record embeds its own signer's public key, or taking a
/// `&SigningPublicKeyBytes`, when it doesn't), which just calls
/// [`Self::verify_signature_with`] under the hood.
pub trait SignedRecord: Canonicalize {
    /// This record type's domain-separation label for signing (see
    /// [`crate::canonical::labels`]).
    const SIGN_LABEL: &'static str;

    /// Borrows this record's own signature field (`signature` on most
    /// records, `proof_signature` on [`crate::records::JoinRequest`]).
    ///
    /// Implementors must return the actual signature field — never a
    /// value also covered by [`Canonicalize::write_canonical`], or
    /// verification would be circular.
    fn signature(&self) -> &SignatureBytes;

    /// Verifies `self`'s signature against `public_key`.
    ///
    /// This checks only that `public_key` produced `self.signature()`
    /// over `self`'s canonical encoding; it says nothing about whether
    /// `public_key` was authorized to sign this record.
    fn verify_signature_with(&self, public_key: &SigningPublicKeyBytes) -> Result<(), ProtocolError>
    where
        Self: Sized,
    {
        verify(Self::SIGN_LABEL, self, public_key, self.signature())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CanonicalBytes;

    struct Sample<'a>(&'a str);

    impl Canonicalize for Sample<'_> {
        fn write_canonical(&self, buf: &mut CanonicalBytes) {
            buf.push_str(self.0);
        }
    }

    #[test]
    fn generated_keypairs_have_distinct_public_keys() {
        let a = SigningKeyPair::generate();
        let b = SigningKeyPair::generate();
        assert_ne!(a.public_key().as_bytes(), b.public_key().as_bytes());
    }

    #[test]
    fn valid_signature_verifies() {
        let keypair = SigningKeyPair::generate();
        let value = Sample("hello");
        let signature = keypair.sign("test-label", &value);

        verify("test-label", &value, &keypair.public_key(), &signature)
            .expect("a freshly produced signature should verify");
    }

    #[test]
    fn modified_value_fails_verification() {
        let keypair = SigningKeyPair::generate();
        let signature = keypair.sign("test-label", &Sample("hello"));

        let err = verify(
            "test-label",
            &Sample("goodbye"),
            &keypair.public_key(),
            &signature,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn modified_label_fails_verification() {
        let keypair = SigningKeyPair::generate();
        let value = Sample("hello");
        let signature = keypair.sign("test-label", &value);

        let err = verify("different-label", &value, &keypair.public_key(), &signature).unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn wrong_public_key_fails_verification() {
        let keypair = SigningKeyPair::generate();
        let other_keypair = SigningKeyPair::generate();
        let value = Sample("hello");
        let signature = keypair.sign("test-label", &value);

        let err = verify(
            "test-label",
            &value,
            &other_keypair.public_key(),
            &signature,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn malformed_signature_bytes_are_rejected_at_construction() {
        let err = SignatureBytes::from_bytes(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidSignature { .. }));
    }

    #[test]
    fn malformed_public_key_bytes_are_rejected_at_construction() {
        let err = SigningPublicKeyBytes::from_bytes(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidPublicKey { .. }));
    }

    #[test]
    fn structurally_invalid_public_key_is_rejected_at_verification() {
        // 32 bytes (passes length-only construction), but not a valid
        // compressed Edwards point: `ed25519_dalek::VerifyingKey::from_bytes`
        // rejects it lazily, at verification time, not at construction.
        // (Not every all-same-byte or high-bit pattern is invalid here —
        // e.g. all-0xFF *is* a valid point for this curve — so this
        // specific pattern was confirmed against the actual
        // `ed25519-dalek` v3.0.0 decompression logic rather than assumed.)
        let mut bogus_key_bytes = [0u8; 32];
        bogus_key_bytes[31] = 0xFF;
        let bogus_key = SigningPublicKeyBytes::new_unchecked_for_test(bogus_key_bytes);
        let bogus_signature = SignatureBytes::new_unchecked_for_test([0u8; 64]);

        let err = verify("test-label", &Sample("hello"), &bogus_key, &bogus_signature).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidPublicKey { .. }));
    }

    #[test]
    fn from_bytes_reconstructs_the_same_public_key() {
        let original = SigningKeyPair::generate();
        let seed = original.to_bytes();

        let reloaded = SigningKeyPair::from_bytes(&seed);

        assert_eq!(
            original.public_key().as_bytes(),
            reloaded.public_key().as_bytes()
        );
    }

    #[test]
    fn from_bytes_reconstructs_a_keypair_that_produces_verifiable_signatures() {
        let original = SigningKeyPair::generate();
        let seed = original.to_bytes();
        let reloaded = SigningKeyPair::from_bytes(&seed);

        let value = Sample("hello");
        let signature = reloaded.sign("test-label", &value);

        verify("test-label", &value, &original.public_key(), &signature).expect(
            "a signature from a reloaded keypair should verify against the original public key",
        );
    }

    #[test]
    fn to_bytes_is_deterministic() {
        let keypair = SigningKeyPair::generate();
        assert_eq!(keypair.to_bytes(), keypair.to_bytes());
    }

    #[test]
    fn sign_is_deterministic_for_the_same_key_and_input() {
        let keypair = SigningKeyPair::generate();
        let value = Sample("hello");
        let a = keypair.sign("test-label", &value);
        let b = keypair.sign("test-label", &value);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }
}
