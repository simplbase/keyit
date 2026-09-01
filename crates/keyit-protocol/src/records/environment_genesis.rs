use std::path::PathBuf;

use crate::canonical::{labels, CanonicalBytes, Canonicalize};
use crate::error::ProtocolError;
use crate::ids::{DeviceId, EnvironmentId, ProjectId};
use crate::primitives::{HashBytes, SignatureBytes, SigningPublicKeyBytes, Timestamp};
use crate::signing::SignedRecord;
use crate::version::ProtocolVersion;

/// The document format an environment's revisions contain.
///
/// `docs/protocol/keyit-protocol-v1.md` states "V1 officially supports
/// `dotenv/v1`" without ruling out future document types, so this is
/// `#[non_exhaustive]` rather than a bare boolean or unit struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DocumentType {
    /// A dotenv-style `KEY=value` document, v1 format.
    DotenvV1,
}

impl DocumentType {
    /// Canonical string form, matching the protocol document's
    /// `dotenv/v1` notation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DotenvV1 => "dotenv/v1",
        }
    }
}

/// The signed genesis document that creates an environment within a
/// project.
///
/// Conceptual record from the "Environment Model" section of
/// `docs/protocol/keyit-protocol-v1.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentGenesis {
    /// Protocol version this genesis document was created under.
    pub protocol_version: ProtocolVersion,
    /// The project this environment belongs to.
    pub project_id: ProjectId,
    /// The environment's stable identifier.
    pub environment_id: EnvironmentId,
    /// Untrusted human-readable label, e.g. `"development"`.
    pub environment_label: String,
    /// The document format this environment's revisions will contain.
    pub document_type: DocumentType,
    /// Machine-local materialization hint (e.g. `.env.local`). Not
    /// protocol identity: two devices may map the same environment to
    /// different local paths.
    pub local_path_hint: PathBuf,
    /// When this environment was created.
    pub created_at: Timestamp,
    /// The device that ran `keyit env add`.
    pub created_by_device_id: DeviceId,
    /// Hash of the parent project's genesis document, binding this
    /// environment to a specific project genesis.
    pub parent_project_genesis_hash: HashBytes,
    /// Signature over the rest of this document by the creating device.
    pub signature: SignatureBytes,
}

impl Canonicalize for EnvironmentGenesis {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.protocol_version.as_str());
        buf.push_str(self.project_id.as_str());
        buf.push_str(self.environment_id.as_str());
        buf.push_str(&self.environment_label);
        buf.push_str(self.document_type.as_str());
        // `local_path_hint` is not protocol identity (see its own field
        // doc comment) but the record's doc comment says the signature
        // covers "the rest of this document" — every field but
        // `signature` — so it is still included here. `to_string_lossy`
        // is used rather than a byte-exact path encoding: a non-UTF-8
        // path is already an edge case Keyit does not attempt to
        // round-trip exactly, and a machine-local path hint losing
        // exact fidelity for non-UTF-8 bytes in its *signed* encoding is
        // an acceptable, documented limitation, not a protocol identity
        // concern.
        buf.push_str(&self.local_path_hint.to_string_lossy());
        buf.push_u64(self.created_at.unix_seconds());
        buf.push_str(self.created_by_device_id.as_str());
        buf.push_bytes(self.parent_project_genesis_hash.as_bytes());
    }
}

impl SignedRecord for EnvironmentGenesis {
    const SIGN_LABEL: &'static str = labels::SIGN_ENVIRONMENT_GENESIS;

    fn signature(&self) -> &SignatureBytes {
        &self.signature
    }
}

impl EnvironmentGenesis {
    /// Verifies this environment genesis document's signature against
    /// `public_key`.
    ///
    /// `EnvironmentGenesis` does not embed `created_by_device_id`'s
    /// public key, only its [`DeviceId`] — the caller must supply the
    /// matching public key, typically looked up from that device's own
    /// [`crate::records::DeviceIdentity`].
    pub fn verify_signature(
        &self,
        public_key: &SigningPublicKeyBytes,
    ) -> Result<(), ProtocolError> {
        self.verify_signature_with(public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_preimage;
    use crate::signing::SigningKeyPair;

    fn sample_genesis() -> EnvironmentGenesis {
        EnvironmentGenesis {
            protocol_version: ProtocolVersion::CURRENT,
            project_id: ProjectId::new_unchecked_for_test("9e107d9d372bb682"),
            environment_id: EnvironmentId::new_unchecked_for_test("e807f1fcf82d132f"),
            environment_label: "development".to_string(),
            document_type: DocumentType::DotenvV1,
            local_path_hint: PathBuf::from(".env.local"),
            created_at: Timestamp::from_unix_seconds(1_755_878_400),
            created_by_device_id: DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            parent_project_genesis_hash: HashBytes::new_unchecked_for_test([3u8; 32]),
            signature: SignatureBytes::new_unchecked_for_test([0u8; 64]),
        }
    }

    #[test]
    fn document_type_renders_expected_string() {
        assert_eq!(DocumentType::DotenvV1.as_str(), "dotenv/v1");
    }

    #[test]
    fn constructs_with_expected_fields() {
        let genesis = sample_genesis();

        assert_eq!(genesis.environment_label, "development");
        assert_eq!(genesis.document_type, DocumentType::DotenvV1);
        assert_eq!(genesis.local_path_hint, PathBuf::from(".env.local"));
    }

    #[test]
    fn canonical_preimage_excludes_signature() {
        let mut with_different_signature = sample_genesis();
        with_different_signature.signature = SignatureBytes::new_unchecked_for_test([0xFFu8; 64]);

        let a = canonical_preimage(labels::SIGN_ENVIRONMENT_GENESIS, &sample_genesis());
        let b = canonical_preimage(labels::SIGN_ENVIRONMENT_GENESIS, &with_different_signature);
        assert_eq!(a, b);
    }

    #[test]
    fn changing_environment_label_changes_canonical_preimage() {
        let mut other = sample_genesis();
        other.environment_label = "staging".to_string();

        let a = canonical_preimage(labels::SIGN_ENVIRONMENT_GENESIS, &sample_genesis());
        let b = canonical_preimage(labels::SIGN_ENVIRONMENT_GENESIS, &other);
        assert_ne!(a, b);
    }

    #[test]
    fn signed_genesis_verifies_against_the_correct_key() {
        let keypair = SigningKeyPair::generate();
        let mut genesis = sample_genesis();
        genesis.signature = keypair.sign(labels::SIGN_ENVIRONMENT_GENESIS, &genesis);

        genesis
            .verify_signature(&keypair.public_key())
            .expect("a genuinely signed environment genesis should verify");
    }

    #[test]
    fn genesis_signed_by_a_different_key_fails_verification() {
        let keypair = SigningKeyPair::generate();
        let other_keypair = SigningKeyPair::generate();
        let mut genesis = sample_genesis();
        genesis.signature = keypair.sign(labels::SIGN_ENVIRONMENT_GENESIS, &genesis);

        let err = genesis
            .verify_signature(&other_keypair.public_key())
            .unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::SignatureVerificationFailed { .. }
        ));
    }
}
