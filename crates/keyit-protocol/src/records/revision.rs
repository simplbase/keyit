use crate::canonical::{labels, CanonicalBytes, Canonicalize};
use crate::error::ProtocolError;
use crate::ids::{DeviceId, EnvironmentId, ProjectId, RevisionId};
use crate::primitives::{HashBytes, SignatureBytes, SigningPublicKeyBytes, Timestamp};
use crate::signing::SignedRecord;

/// One entry in an environment's append-only signed revision chain.
///
/// Conceptual record from the "Revision Chain" section of
/// `docs/protocol/keyit-protocol-v1.md`. `encrypted_payload_ref` is kept
/// as an opaque `String` because relay payload storage is still a
/// higher-level concern. `keyit-cli`'s local-only push/pull flow stores
/// local encrypted payloads and uses a local reference string, but that
/// is not a protocol wire/storage format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    /// This revision's stable identifier.
    pub revision_id: RevisionId,
    /// The project this revision belongs to.
    pub project_id: ProjectId,
    /// The environment this revision belongs to.
    pub environment_id: EnvironmentId,
    /// The previous revision in this environment's chain. `None` only
    /// for an environment's first revision.
    pub parent_revision_id: Option<RevisionId>,
    /// Hash of the parent revision. `None` only for an environment's
    /// first revision.
    pub parent_revision_hash: Option<HashBytes>,
    /// Hash of the (still encrypted) payload this revision points to.
    pub payload_hash: HashBytes,
    /// Opaque reference to where the encrypted payload is stored.
    pub encrypted_payload_ref: String,
    /// The device that authored (pushed) this revision.
    pub author_device_id: DeviceId,
    /// When this revision was created.
    pub created_at: Timestamp,
    /// Optional non-secret human-readable summary of the change. Must
    /// never contain secret values (Frozen rule 8 under "Push").
    pub change_summary: Option<String>,
    /// Signature over this revision's metadata and payload hash.
    pub signature: SignatureBytes,
}

impl Revision {
    /// Whether this is an environment's first revision (no parent).
    pub fn is_root(&self) -> bool {
        self.parent_revision_id.is_none()
    }

    /// Verifies this revision's signature against `public_key`.
    ///
    /// `Revision` does not embed `author_device_id`'s public key — the
    /// caller must supply it, typically looked up from that device's
    /// own [`crate::records::DeviceIdentity`]. Matches the protocol
    /// document's "Revision Chain" section: the signature covers the
    /// revision metadata and payload hash. [`Canonicalize`] covers every
    /// field except `signature` itself.
    pub fn verify_signature(
        &self,
        public_key: &SigningPublicKeyBytes,
    ) -> Result<(), ProtocolError> {
        self.verify_signature_with(public_key)
    }
}

impl Canonicalize for Revision {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.revision_id.as_str());
        buf.push_str(self.project_id.as_str());
        buf.push_str(self.environment_id.as_str());
        buf.push_opt_bytes(
            self.parent_revision_id
                .as_ref()
                .map(|id| id.as_str().as_bytes()),
        );
        buf.push_opt_bytes(self.parent_revision_hash.as_ref().map(HashBytes::as_bytes));
        buf.push_bytes(self.payload_hash.as_bytes());
        buf.push_str(&self.encrypted_payload_ref);
        buf.push_str(self.author_device_id.as_str());
        buf.push_u64(self.created_at.unix_seconds());
        buf.push_opt_bytes(self.change_summary.as_deref().map(str::as_bytes));
    }
}

impl SignedRecord for Revision {
    const SIGN_LABEL: &'static str = labels::SIGN_REVISION;

    fn signature(&self) -> &SignatureBytes {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_preimage;
    use crate::signing::SigningKeyPair;

    fn sample_revision(parent: Option<RevisionId>) -> Revision {
        Revision {
            revision_id: RevisionId::new_unchecked_for_test("1f3870be274f6c49"),
            project_id: ProjectId::new_unchecked_for_test("9e107d9d372bb682"),
            environment_id: EnvironmentId::new_unchecked_for_test("e807f1fcf82d132f"),
            parent_revision_id: parent.clone(),
            parent_revision_hash: parent.map(|_| HashBytes::new_unchecked_for_test([4u8; 32])),
            payload_hash: HashBytes::new_unchecked_for_test([5u8; 32]),
            encrypted_payload_ref: "relay://test-payload".to_string(),
            author_device_id: DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            created_at: Timestamp::from_unix_seconds(1_755_878_400),
            change_summary: Some("initial revision".to_string()),
            signature: SignatureBytes::new_unchecked_for_test([0u8; 64]),
        }
    }

    #[test]
    fn constructs_with_expected_fields() {
        let revision = sample_revision(None);
        assert!(revision.is_root());
        assert_eq!(revision.change_summary.as_deref(), Some("initial revision"));
    }

    #[test]
    fn non_root_revision_carries_parent() {
        let parent_id = RevisionId::new_unchecked_for_test("1f3870be274f6c50");
        let revision = sample_revision(Some(parent_id.clone()));
        assert!(!revision.is_root());
        assert_eq!(revision.parent_revision_id, Some(parent_id));
    }

    #[test]
    fn canonical_preimage_excludes_signature() {
        let mut with_different_signature = sample_revision(None);
        with_different_signature.signature = SignatureBytes::new_unchecked_for_test([0xFFu8; 64]);

        let a = canonical_preimage(labels::SIGN_REVISION, &sample_revision(None));
        let b = canonical_preimage(labels::SIGN_REVISION, &with_different_signature);
        assert_eq!(a, b);
    }

    #[test]
    fn changing_payload_hash_changes_canonical_preimage() {
        let mut other = sample_revision(None);
        other.payload_hash = HashBytes::new_unchecked_for_test([9u8; 32]);

        let a = canonical_preimage(labels::SIGN_REVISION, &sample_revision(None));
        let b = canonical_preimage(labels::SIGN_REVISION, &other);
        assert_ne!(a, b);
    }

    #[test]
    fn root_and_non_root_revisions_have_different_preimages() {
        let parent_id = RevisionId::new_unchecked_for_test("1f3870be274f6c50");

        let a = canonical_preimage(labels::SIGN_REVISION, &sample_revision(None));
        let b = canonical_preimage(labels::SIGN_REVISION, &sample_revision(Some(parent_id)));
        assert_ne!(a, b);
    }

    #[test]
    fn signed_revision_verifies_against_the_correct_key() {
        let keypair = SigningKeyPair::generate();
        let mut revision = sample_revision(None);
        revision.signature = keypair.sign(labels::SIGN_REVISION, &revision);

        revision
            .verify_signature(&keypair.public_key())
            .expect("a genuinely signed revision should verify");
    }

    #[test]
    fn revision_signed_by_a_different_key_fails_verification() {
        let keypair = SigningKeyPair::generate();
        let other_keypair = SigningKeyPair::generate();
        let mut revision = sample_revision(None);
        revision.signature = keypair.sign(labels::SIGN_REVISION, &revision);

        let err = revision
            .verify_signature(&other_keypair.public_key())
            .unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::SignatureVerificationFailed { .. }
        ));
    }
}
