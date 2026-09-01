use crate::canonical::{labels, CanonicalBytes, Canonicalize};
use crate::error::ProtocolError;
use crate::ids::{DeviceId, EnvironmentId, ProjectId};
use crate::primitives::{SignatureBytes, SigningPublicKeyBytes, Timestamp};
use crate::records::role::Role;
use crate::signing::SignedRecord;

/// The signed record that grants a device project/environment access.
///
/// Conceptual record from the "Approval" section of
/// `docs/protocol/keyit-protocol-v1.md`. This is the cryptographic act
/// that grants access; a [`crate::records::JoinRequest`] alone grants
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The project access is being granted for.
    pub project_id: ProjectId,
    /// The device being approved.
    pub approved_device_id: DeviceId,
    /// Environments the approved device may access.
    pub approved_environment_ids: Vec<EnvironmentId>,
    /// Role granted to the approved device.
    pub role: Role,
    /// The already-authorized owner/admin device performing the
    /// approval.
    pub approved_by_device_id: DeviceId,
    /// When this approval was created.
    pub created_at: Timestamp,
    /// Signature over the rest of this record by the approving device.
    pub signature: SignatureBytes,
}

impl Canonicalize for Approval {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.project_id.as_str());
        buf.push_str(self.approved_device_id.as_str());
        buf.push_list(&self.approved_environment_ids, |buf, id| {
            buf.push_str(id.as_str());
        });
        buf.push_str(self.role.as_str());
        buf.push_str(self.approved_by_device_id.as_str());
        buf.push_u64(self.created_at.unix_seconds());
    }
}

impl SignedRecord for Approval {
    const SIGN_LABEL: &'static str = labels::SIGN_APPROVAL;

    fn signature(&self) -> &SignatureBytes {
        &self.signature
    }
}

impl Approval {
    /// Verifies this approval's signature against `public_key`.
    ///
    /// `Approval` does not embed `approved_by_device_id`'s public key —
    /// the caller must supply it, typically looked up from that
    /// device's own [`crate::records::DeviceIdentity`] (which must
    /// itself already be an authorized owner/admin — a check this
    /// method does not perform.
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

    fn sample_approval() -> Approval {
        Approval {
            project_id: ProjectId::new_unchecked_for_test("9e107d9d372bb682"),
            approved_device_id: DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            approved_environment_ids: vec![EnvironmentId::new_unchecked_for_test(
                "e807f1fcf82d132f",
            )],
            role: Role::Member,
            approved_by_device_id: DeviceId::new_unchecked_for_test("d41d8cd98f00b205"),
            created_at: Timestamp::from_unix_seconds(1_755_878_400),
            signature: SignatureBytes::new_unchecked_for_test([0u8; 64]),
        }
    }

    #[test]
    fn constructs_with_expected_fields() {
        let approval = sample_approval();

        assert_eq!(approval.role, Role::Member);
        assert_ne!(approval.approved_device_id, approval.approved_by_device_id);
    }

    #[test]
    fn canonical_preimage_excludes_signature() {
        let mut with_different_signature = sample_approval();
        with_different_signature.signature = SignatureBytes::new_unchecked_for_test([0xFFu8; 64]);

        let a = canonical_preimage(labels::SIGN_APPROVAL, &sample_approval());
        let b = canonical_preimage(labels::SIGN_APPROVAL, &with_different_signature);
        assert_eq!(a, b);
    }

    #[test]
    fn changing_role_changes_canonical_preimage() {
        let mut other = sample_approval();
        other.role = Role::Admin;

        let a = canonical_preimage(labels::SIGN_APPROVAL, &sample_approval());
        let b = canonical_preimage(labels::SIGN_APPROVAL, &other);
        assert_ne!(a, b);
    }

    #[test]
    fn signed_approval_verifies_against_the_correct_key() {
        let keypair = SigningKeyPair::generate();
        let mut approval = sample_approval();
        approval.signature = keypair.sign(labels::SIGN_APPROVAL, &approval);

        approval
            .verify_signature(&keypair.public_key())
            .expect("a genuinely signed approval should verify");
    }

    #[test]
    fn approval_signed_by_a_different_key_fails_verification() {
        let keypair = SigningKeyPair::generate();
        let other_keypair = SigningKeyPair::generate();
        let mut approval = sample_approval();
        approval.signature = keypair.sign(labels::SIGN_APPROVAL, &approval);

        let err = approval
            .verify_signature(&other_keypair.public_key())
            .unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::SignatureVerificationFailed { .. }
        ));
    }
}
