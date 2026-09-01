//! Environment payload encryption and DEK wrapping.
//!
//! Keyit uses two different key classes for environment data:
//!
//! - an environment data encryption key (DEK), a random 32-byte
//!   symmetric key used with AES-256-GCM to encrypt one normalized
//!   environment payload;
//! - a device X25519 key-agreement keypair used only to wrap DEKs for
//!   authorized recipient devices.
//!
//! This module deliberately does not define relay storage paths,
//! revision creation, or local keychain persistence. It provides the
//! cryptographic operations those higher-level workflows will call.

use std::fmt;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::ProtocolError;
use crate::primitives::PublicKeyBytes;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const PAYLOAD_ALGORITHM: &str = "keyit:v1:aes-256-gcm:environment-payload";
const WRAP_ALGORITHM: &str = "keyit:v1:x25519-hkdf-sha256-aes-256-gcm:dek-wrap";
const WRAP_HKDF_INFO: &[u8] = b"keyit:v1:dek-wrap:aes-256-gcm";

/// A random 32-byte environment data encryption key.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvironmentDataKey([u8; KEY_LEN]);

impl EnvironmentDataKey {
    /// Generates a fresh environment DEK with the operating system
    /// CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::fill(&mut bytes).expect("OS CSPRNG should be available");
        Self(bytes)
    }

    /// Validates and wraps a raw 32-byte DEK.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let array: [u8; KEY_LEN] =
            bytes
                .try_into()
                .map_err(|_| ProtocolError::InvalidSymmetricKey {
                    reason: format!("expected {KEY_LEN} bytes, found {}", bytes.len()),
                })?;
        Ok(Self(array))
    }

    /// Borrows the raw key bytes.
    ///
    /// This is secret key material. Callers should avoid logging or
    /// persisting it; it exists so local authorized devices can encrypt,
    /// decrypt, and compare keys in tests.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for EnvironmentDataKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for EnvironmentDataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EnvironmentDataKey")
            .field(&format_args!("{KEY_LEN} bytes"))
            .finish()
    }
}

/// A local X25519 key-agreement keypair.
pub struct KeyAgreementKeyPair(StaticSecret);

impl KeyAgreementKeyPair {
    /// Generates a fresh X25519 private key using the operating system
    /// CSPRNG.
    pub fn generate() -> Self {
        let mut secret = [0u8; KEY_LEN];
        getrandom::fill(&mut secret).expect("OS CSPRNG should be available");
        let keypair = Self(StaticSecret::from(secret));
        secret.zeroize();
        keypair
    }

    /// Reconstructs a keypair from a previously generated 32-byte X25519
    /// private key.
    pub fn from_bytes(secret: &[u8; KEY_LEN]) -> Self {
        Self(StaticSecret::from(*secret))
    }

    /// Returns the raw 32-byte X25519 private key.
    ///
    /// This is private key material. It exists only for callers that
    /// persist the key outside project metadata.
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0.to_bytes()
    }

    /// This keypair's public key, in Keyit's fixed-size byte wrapper.
    pub fn public_key(&self) -> PublicKeyBytes {
        let public = PublicKey::from(&self.0);
        PublicKeyBytes::from_bytes(public.as_bytes()).expect("X25519 public keys are 32 bytes")
    }
}

impl fmt::Debug for KeyAgreementKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyAgreementKeyPair")
            .field(&"X25519 key-agreement keypair")
            .finish()
    }
}

/// AES-GCM encrypted normalized environment payload bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedPayload {
    /// Algorithm identifier for storage and future migrations.
    pub algorithm: &'static str,
    /// 96-bit AES-GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext including the authentication tag.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for EncryptedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedPayload")
            .field("algorithm", &self.algorithm)
            .field("nonce", &format_args!("{} bytes", self.nonce.len()))
            .field(
                "ciphertext",
                &format_args!("{} bytes", self.ciphertext.len()),
            )
            .finish()
    }
}

/// A DEK encrypted for one recipient device.
#[derive(Clone, PartialEq, Eq)]
pub struct WrappedDataKey {
    /// Algorithm identifier for storage and future migrations.
    pub algorithm: &'static str,
    /// Ephemeral X25519 public key generated for this wrapping operation.
    pub ephemeral_public_key: PublicKeyBytes,
    /// 96-bit AES-GCM nonce used for the wrapped DEK ciphertext.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext of the 32-byte DEK, including the authentication tag.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for WrappedDataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrappedDataKey")
            .field("algorithm", &self.algorithm)
            .field("ephemeral_public_key", &self.ephemeral_public_key)
            .field("nonce", &format_args!("{} bytes", self.nonce.len()))
            .field(
                "ciphertext",
                &format_args!("{} bytes", self.ciphertext.len()),
            )
            .finish()
    }
}

/// Encrypts normalized environment payload bytes with `dek`.
///
/// `associated_data` should be stable, non-secret context that higher
/// layers also know while decrypting, such as project/environment IDs
/// and document type. It is authenticated but not encrypted.
pub fn encrypt_payload(
    dek: &EnvironmentDataKey,
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<EncryptedPayload, ProtocolError> {
    let nonce = random_nonce();
    let cipher = cipher_from_key(dek.as_bytes())?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| ProtocolError::EncryptionFailed {
            operation: "environment payload encryption",
        })?;

    Ok(EncryptedPayload {
        algorithm: PAYLOAD_ALGORITHM,
        nonce,
        ciphertext,
    })
}

/// Decrypts an encrypted environment payload.
pub fn decrypt_payload(
    dek: &EnvironmentDataKey,
    associated_data: &[u8],
    encrypted: &EncryptedPayload,
) -> Result<Vec<u8>, ProtocolError> {
    let cipher = cipher_from_key(dek.as_bytes())?;
    cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            Payload {
                msg: &encrypted.ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| ProtocolError::DecryptionFailed {
            operation: "environment payload decryption",
        })
}

/// Wraps `dek` for a recipient device's X25519 public key.
///
/// `context` is authenticated and also used as HKDF salt. Callers should
/// include the project ID, environment ID, recipient device ID, and any
/// key-version material available at that layer.
pub fn wrap_dek_for_device(
    dek: &EnvironmentDataKey,
    recipient_public_key: &PublicKeyBytes,
    context: &[u8],
) -> Result<WrappedDataKey, ProtocolError> {
    let ephemeral = KeyAgreementKeyPair::generate();
    let ephemeral_public_key = ephemeral.public_key();
    let mut wrapping_key = derive_wrapping_key(&ephemeral, recipient_public_key, context)?;
    let nonce = random_nonce();
    let cipher = cipher_from_key(&wrapping_key)?;
    wrapping_key.zeroize();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: dek.as_bytes(),
                aad: context,
            },
        )
        .map_err(|_| ProtocolError::EncryptionFailed {
            operation: "environment DEK wrapping",
        })?;

    Ok(WrappedDataKey {
        algorithm: WRAP_ALGORITHM,
        ephemeral_public_key,
        nonce,
        ciphertext,
    })
}

/// Unwraps a DEK encrypted for `recipient_keypair`.
pub fn unwrap_dek_for_device(
    wrapped: &WrappedDataKey,
    recipient_keypair: &KeyAgreementKeyPair,
    context: &[u8],
) -> Result<EnvironmentDataKey, ProtocolError> {
    let mut wrapping_key =
        derive_wrapping_key(recipient_keypair, &wrapped.ephemeral_public_key, context)?;
    let cipher = cipher_from_key(&wrapping_key)?;
    wrapping_key.zeroize();
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&wrapped.nonce),
            Payload {
                msg: &wrapped.ciphertext,
                aad: context,
            },
        )
        .map_err(|_| ProtocolError::DecryptionFailed {
            operation: "environment DEK unwrapping",
        })?;

    let dek = EnvironmentDataKey::from_bytes(&plaintext)?;
    Ok(dek)
}

fn derive_wrapping_key(
    own_keypair: &KeyAgreementKeyPair,
    peer_public_key: &PublicKeyBytes,
    context: &[u8],
) -> Result<[u8; KEY_LEN], ProtocolError> {
    let peer = PublicKey::from(peer_public_key.as_array());
    let shared_secret = own_keypair.0.diffie_hellman(&peer);
    let hkdf = Hkdf::<Sha256>::new(Some(context), shared_secret.as_bytes());
    let mut key = [0u8; KEY_LEN];
    hkdf.expand(WRAP_HKDF_INFO, &mut key)
        .map_err(|_| ProtocolError::EncryptionFailed {
            operation: "environment DEK wrapping key derivation",
        })?;
    Ok(key)
}

fn cipher_from_key(key: &[u8]) -> Result<Aes256Gcm, ProtocolError> {
    Aes256Gcm::new_from_slice(key).map_err(|_| ProtocolError::InvalidSymmetricKey {
        reason: format!("expected {KEY_LEN} bytes, found {}", key.len()),
    })
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("OS CSPRNG should be available");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: &[u8] = b"kvp_test:kve_development:kvd_recipient:v1";

    #[test]
    fn generated_deks_are_distinct() {
        let a = EnvironmentDataKey::generate();
        let b = EnvironmentDataKey::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn environment_data_key_rejects_wrong_length() {
        let err = EnvironmentDataKey::from_bytes(&[1u8; 31]).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidSymmetricKey { .. }));
    }

    #[test]
    fn generated_x25519_keypairs_have_public_keys() {
        let keypair = KeyAgreementKeyPair::generate();
        assert_eq!(keypair.public_key().len(), KEY_LEN);
    }

    #[test]
    fn key_agreement_keypair_round_trips_private_bytes() {
        let original = KeyAgreementKeyPair::generate();
        let reloaded = KeyAgreementKeyPair::from_bytes(&original.to_bytes());

        assert_eq!(
            original.public_key().as_bytes(),
            reloaded.public_key().as_bytes()
        );
    }

    #[test]
    fn payload_encrypt_decrypt_round_trips() {
        let dek = EnvironmentDataKey::generate();
        let plaintext = b"API_KEY=super-secret\nLOG_LEVEL=debug\n";
        let encrypted = encrypt_payload(&dek, CONTEXT, plaintext).expect("encrypt");

        assert_ne!(encrypted.ciphertext, plaintext);
        let decrypted = decrypt_payload(&dek, CONTEXT, &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn payload_decryption_fails_with_wrong_context() {
        let dek = EnvironmentDataKey::generate();
        let encrypted = encrypt_payload(&dek, CONTEXT, b"SECRET=value\n").expect("encrypt");

        let err = decrypt_payload(&dek, b"other-context", &encrypted).unwrap_err();
        assert!(matches!(err, ProtocolError::DecryptionFailed { .. }));
    }

    #[test]
    fn payload_decryption_fails_with_wrong_dek() {
        let dek = EnvironmentDataKey::generate();
        let wrong = EnvironmentDataKey::generate();
        let encrypted = encrypt_payload(&dek, CONTEXT, b"SECRET=value\n").expect("encrypt");

        let err = decrypt_payload(&wrong, CONTEXT, &encrypted).unwrap_err();
        assert!(matches!(err, ProtocolError::DecryptionFailed { .. }));
    }

    #[test]
    fn wrapping_and_unwrapping_round_trips_dek() {
        let dek = EnvironmentDataKey::generate();
        let recipient = KeyAgreementKeyPair::generate();
        let wrapped =
            wrap_dek_for_device(&dek, &recipient.public_key(), CONTEXT).expect("wrap DEK");

        let unwrapped = unwrap_dek_for_device(&wrapped, &recipient, CONTEXT).expect("unwrap DEK");
        assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn unwrapping_fails_for_wrong_recipient() {
        let dek = EnvironmentDataKey::generate();
        let recipient = KeyAgreementKeyPair::generate();
        let wrong_recipient = KeyAgreementKeyPair::generate();
        let wrapped =
            wrap_dek_for_device(&dek, &recipient.public_key(), CONTEXT).expect("wrap DEK");

        let err = unwrap_dek_for_device(&wrapped, &wrong_recipient, CONTEXT).unwrap_err();
        assert!(matches!(err, ProtocolError::DecryptionFailed { .. }));
    }

    #[test]
    fn unwrapping_fails_for_wrong_context() {
        let dek = EnvironmentDataKey::generate();
        let recipient = KeyAgreementKeyPair::generate();
        let wrapped =
            wrap_dek_for_device(&dek, &recipient.public_key(), CONTEXT).expect("wrap DEK");

        let err = unwrap_dek_for_device(&wrapped, &recipient, b"other-context").unwrap_err();
        assert!(matches!(err, ProtocolError::DecryptionFailed { .. }));
    }

    #[test]
    fn debug_output_does_not_print_secret_material() {
        let dek = EnvironmentDataKey::from_bytes(&[0xAB; KEY_LEN]).expect("DEK");
        let debug = format!("{dek:?}");
        assert!(debug.contains("32 bytes"));
        assert!(!debug.contains("171"));
        assert!(!debug.contains("AB"));
        assert!(!debug.contains("ab"));
    }
}
