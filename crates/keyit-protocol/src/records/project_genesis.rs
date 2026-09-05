use crate::canonical::{labels, CanonicalBytes, Canonicalize};
use crate::error::ProtocolError;
use crate::ids::{DeviceId, ProjectId};
use crate::primitives::{NonceBytes, SignatureBytes, SigningPublicKeyBytes, Timestamp};
use crate::signing::SignedRecord;
use crate::version::ProtocolVersion;

/// The signed genesis document that creates a Keyit project.
///
/// Conceptual record from the "Project Genesis" section of
/// `docs/protocol/keyit-protocol-v1.md`. `project_id` is derived from
/// this document (including `genesis_nonce`, which is what makes project
/// IDs globally unique) — see [`crate::ids::ProjectId::derive`]. This
/// method verifies the signature; project ID consistency is checked by
/// callers that construct or load project metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectGenesis {
    /// Protocol version this genesis document was created under.
    pub protocol_version: ProtocolVersion,
    /// The project's stable identifier, derived from this genesis
    /// document.
    pub project_id: ProjectId,
    /// High-entropy nonce that makes `project_id` globally unique.
    pub genesis_nonce: NonceBytes,
    /// When the project was created.
    pub created_at: Timestamp,
    /// The device that ran `keyit init` and created this project.
    pub creator_device_id: DeviceId,
    /// The creating device's signing public key, so the genesis
    /// signature can be verified without a separate lookup.
    pub creator_device_public_identity: SigningPublicKeyBytes,
    /// Untrusted human-readable label for the project. Never part of
    /// project identity.
    pub project_label: String,
    /// Default relay URL. Configuration, not a trust anchor: see
    /// Frozen rule 12 in "Project Genesis".
    pub default_relay_url: String,
    /// Version of the canonicalization rules used to derive `project_id`
    /// from this document.
    pub canonicalization_version: u32,
    /// Signature over the rest of this document by the creator device's
    /// signing key.
    pub signature: SignatureBytes,
}

impl Canonicalize for ProjectGenesis {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.protocol_version.as_str());
        buf.push_str(self.project_id.as_str());
        buf.push_bytes(self.genesis_nonce.as_bytes());
        buf.push_u64(self.created_at.unix_seconds());
        buf.push_str(self.creator_device_id.as_str());
        buf.push_bytes(self.creator_device_public_identity.as_bytes());
        buf.push_str(&self.project_label);
        buf.push_str(&self.default_relay_url);
        buf.push_u64(u64::from(self.canonicalization_version));
    }
}

impl SignedRecord for ProjectGenesis {
    const SIGN_LABEL: &'static str = labels::SIGN_PROJECT_GENESIS;

    fn signature(&self) -> &SignatureBytes {
        &self.signature
    }
}

impl ProjectGenesis {
    /// Verifies this genesis document's signature against its own
    /// embedded `creator_device_public_identity` — no external key
    /// lookup is needed, since the signer's public key travels with the
    /// record.
    ///
    /// This checks only the cryptographic signature, not whether the
    /// creator device was "allowed" to create this project — project
    /// genesis has no prior authorization to check against by
    /// definition.
    pub fn verify_signature(&self) -> Result<(), ProtocolError> {
        self.verify_signature_with(&self.creator_device_public_identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_preimage;
    use crate::signing::SigningKeyPair;

    fn sample_genesis() -> ProjectGenesis {
        ProjectGenesis {
            protocol_version: ProtocolVersion::CURRENT,
            project_id: ProjectId::new_unchecked_for_test("9e107d9d372bb682"),
            genesis_nonce: NonceBytes::new_unchecked_for_test(vec![9u8; 16]),
            created_at: Timestamp::from_unix_seconds(1_755_878_400),
            creator_device_id: DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            creator_device_public_identity: SigningPublicKeyBytes::new_unchecked_for_test(
                [1u8; 32],
            ),
            project_label: "keyit".to_string(),
            default_relay_url: "https://relay.keyit.sh".to_string(),
            canonicalization_version: 0,
            signature: SignatureBytes::new_unchecked_for_test([0u8; 64]),
        }
    }

    #[test]
    fn constructs_with_expected_fields() {
        let genesis = sample_genesis();

        assert_eq!(genesis.project_label, "keyit");
        assert_eq!(genesis.genesis_nonce.len(), 16);
    }

    #[test]
    fn canonical_preimage_excludes_signature() {
        let mut with_different_signature = sample_genesis();
        with_different_signature.signature = SignatureBytes::new_unchecked_for_test([0xFFu8; 64]);

        let a = canonical_preimage(labels::SIGN_PROJECT_GENESIS, &sample_genesis());
        let b = canonical_preimage(labels::SIGN_PROJECT_GENESIS, &with_different_signature);
        assert_eq!(
            a, b,
            "changing only `signature` must not change the preimage"
        );
    }

    #[test]
    fn changing_project_label_changes_canonical_preimage() {
        let mut other = sample_genesis();
        other.project_label = "different-label".to_string();

        let a = canonical_preimage(labels::SIGN_PROJECT_GENESIS, &sample_genesis());
        let b = canonical_preimage(labels::SIGN_PROJECT_GENESIS, &other);
        assert_ne!(a, b);
    }

    #[test]
    fn signed_genesis_verifies_against_its_own_embedded_key() {
        let keypair = SigningKeyPair::generate();
        let mut genesis = sample_genesis();
        genesis.creator_device_public_identity = keypair.public_key();
        genesis.signature = keypair.sign(labels::SIGN_PROJECT_GENESIS, &genesis);

        genesis
            .verify_signature()
            .expect("a genuinely signed genesis document should verify");
    }

    #[test]
    fn tampered_genesis_fails_verification() {
        let keypair = SigningKeyPair::generate();
        let mut genesis = sample_genesis();
        genesis.creator_device_public_identity = keypair.public_key();
        genesis.signature = keypair.sign(labels::SIGN_PROJECT_GENESIS, &genesis);

        genesis.project_label = "tampered".to_string();

        let err = genesis.verify_signature().unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn genesis_signed_by_a_different_key_fails_verification() {
        let keypair = SigningKeyPair::generate();
        let other_keypair = SigningKeyPair::generate();
        let mut genesis = sample_genesis();
        // Embed the *other* keypair's public key while signing with the
        // first — simulates a forged/mismatched genesis document.
        genesis.creator_device_public_identity = other_keypair.public_key();
        genesis.signature = keypair.sign(labels::SIGN_PROJECT_GENESIS, &genesis);

        let err = genesis.verify_signature().unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::SignatureVerificationFailed { .. }
        ));
    }
}
