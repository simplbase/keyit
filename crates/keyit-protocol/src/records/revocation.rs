use crate::canonical::{labels, CanonicalBytes, Canonicalize};
use crate::error::ProtocolError;
use crate::ids::{DeviceId, EnvironmentId, ProjectId};
use crate::primitives::{SignatureBytes, SigningPublicKeyBytes, Timestamp};
use crate::signing::SignedRecord;

/// The signed record that removes a device's future access.
///
/// Conceptual record from the "Revocation" section of
/// `docs/protocol/keyit-protocol-v1.md`. Revocation is prospective only:
/// it cannot erase plaintext the revoked device already decrypted
/// (Frozen rule 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The project this revocation applies to.
    pub project_id: ProjectId,
    /// The device whose access is being revoked.
    pub revoked_device_id: DeviceId,
    /// Environments whose DEKs must rotate as a result of this
    /// revocation.
    pub affected_environment_ids: Vec<EnvironmentId>,
    /// The already-authorized owner/admin device performing the
    /// revocation.
    pub revoked_by_device_id: DeviceId,
    /// When this revocation was created.
    pub created_at: Timestamp,
    /// Optional non-secret human-readable reason.
    pub reason_optional: Option<String>,
    /// Signature over the rest of this record by the revoking device.
    pub signature: SignatureBytes,
}

impl Canonicalize for Revocation {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.project_id.as_str());
        buf.push_str(self.revoked_device_id.as_str());
        buf.push_list(&self.affected_environment_ids, |buf, id| {
            buf.push_str(id.as_str());
        });
        buf.push_str(self.revoked_by_device_id.as_str());
        buf.push_u64(self.created_at.unix_seconds());
        buf.push_opt_bytes(self.reason_optional.as_deref().map(str::as_bytes));
    }
}

impl SignedRecord for Revocation {
    const SIGN_LABEL: &'static str = labels::SIGN_REVOCATION;

    fn signature(&self) -> &SignatureBytes {
        &self.signature
    }
}

impl Revocation {
    /// Verifies this revocation's signature against `public_key`.
    ///
    /// `Revocation` does not embed `revoked_by_device_id`'s public key —
    /// the caller must supply it, typically looked up from that
    /// device's own [`crate::records::DeviceIdentity`] (which must
    /// itself already be an authorized owner/admin — a check this
    /// method does not perform).
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

    fn sample_revocation(reason: Option<&str>) -> Revocation {
        Revocation {
            project_id: ProjectId::new_unchecked_for_test("9e107d9d372bb682"),
            revoked_device_id: DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            affected_environment_ids: vec![EnvironmentId::new_unchecked_for_test(
                "e807f1fcf82d132f",
            )],
            revoked_by_device_id: DeviceId::new_unchecked_for_test("d41d8cd98f00b205"),
            created_at: Timestamp::from_unix_seconds(1_755_878_400),
            reason_optional: reason.map(str::to_string),
            signature: SignatureBytes::new_unchecked_for_test([0u8; 64]),
        }
    }

    #[test]
    fn constructs_with_expected_fields() {
        let revocation = sample_revocation(Some("device lost"));

        assert_eq!(revocation.reason_optional.as_deref(), Some("device lost"));
        assert_eq!(revocation.affected_environment_ids.len(), 1);
    }

    #[test]
    fn reason_is_optional() {
        let mut revocation = sample_revocation(None);
        revocation.affected_environment_ids = vec![];

        assert!(revocation.reason_optional.is_none());
    }

    #[test]
    fn canonical_preimage_excludes_signature() {
        let mut with_different_signature = sample_revocation(Some("device lost"));
        with_different_signature.signature = SignatureBytes::new_unchecked_for_test([0xFFu8; 64]);

        let a = canonical_preimage(
            labels::SIGN_REVOCATION,
            &sample_revocation(Some("device lost")),
        );
        let b = canonical_preimage(labels::SIGN_REVOCATION, &with_different_signature);
        assert_eq!(a, b);
    }

    #[test]
    fn present_and_absent_reason_have_different_preimages() {
        let a = canonical_preimage(
            labels::SIGN_REVOCATION,
            &sample_revocation(Some("device lost")),
        );
        let b = canonical_preimage(labels::SIGN_REVOCATION, &sample_revocation(None));
        assert_ne!(a, b);
    }

    #[test]
    fn signed_revocation_verifies_against_the_correct_key() {
        let keypair = SigningKeyPair::generate();
        let mut revocation = sample_revocation(Some("device lost"));
        revocation.signature = keypair.sign(labels::SIGN_REVOCATION, &revocation);

        revocation
            .verify_signature(&keypair.public_key())
            .expect("a genuinely signed revocation should verify");
    }

    #[test]
    fn revocation_signed_by_a_different_key_fails_verification() {
        let keypair = SigningKeyPair::generate();
        let other_keypair = SigningKeyPair::generate();
        let mut revocation = sample_revocation(Some("device lost"));
        revocation.signature = keypair.sign(labels::SIGN_REVOCATION, &revocation);

        let err = revocation
            .verify_signature(&other_keypair.public_key())
            .unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::SignatureVerificationFailed { .. }
        ));
    }
}
