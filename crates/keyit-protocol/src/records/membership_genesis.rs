use crate::canonical::{labels, CanonicalBytes, Canonicalize};
use crate::error::ProtocolError;
use crate::ids::{DeviceId, ProjectId};
use crate::primitives::{SignatureBytes, SigningPublicKeyBytes, Timestamp};
use crate::records::role::Role;
use crate::signing::SignedRecord;

/// Where a membership grant's approval originated.
///
/// `docs/protocol/keyit-protocol-v1.md` shows `MembershipGenesis` using
/// the sentinel `approved_by = genesis` for the project creator's
/// implicit first membership, distinct from the `approved_by_device_id`
/// on a later `Approval` record. This enum makes that distinction a
/// closed choice instead of a magic string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalSource {
    /// Granted implicitly by project genesis — the creator device
    /// becomes the first project owner.
    Genesis,
    /// Granted by an explicit, already-authorized device (see
    /// [`crate::records::Approval`]).
    Device(DeviceId),
}

/// The membership record created for the project creator at genesis
/// time.
///
/// Conceptual record from the "Project Genesis" section of
/// `docs/protocol/keyit-protocol-v1.md`. Every other member's access is
/// granted later via [`crate::records::Approval`], not this record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipGenesis {
    /// The project this membership belongs to.
    pub project_id: ProjectId,
    /// The device granted membership (the project creator).
    pub member_device_id: DeviceId,
    /// The creator's role. Always [`Role::Owner`] per the frozen rules,
    /// but not enforced by this struct's constructor since role
    /// enforcement belongs to whatever code eventually builds this
    /// record from a verified `ProjectGenesis`.
    pub role: Role,
    /// Always [`ApprovalSource::Genesis`] for this record; kept as a
    /// full field (rather than implied) so the record's shape matches
    /// the spec's `approved_by` field directly.
    pub approved_by: ApprovalSource,
    /// When this membership was created.
    pub created_at: Timestamp,
    /// Signature over the rest of this record.
    pub signature: SignatureBytes,
}

impl Canonicalize for MembershipGenesis {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.project_id.as_str());
        buf.push_str(self.member_device_id.as_str());
        buf.push_str(self.role.as_str());
        // `ApprovalSource` has no shared canonical string form the way
        // `Role`/`DocumentType`/`InviteStatus` do — it is either a bare
        // sentinel or wraps a `DeviceId` — so it is encoded directly
        // here as a tag byte (0 = Genesis, 1 = Device) followed by the
        // device id when present, rather than via a shared `as_str`.
        match &self.approved_by {
            ApprovalSource::Genesis => {
                buf.push_u8(0);
            }
            ApprovalSource::Device(device_id) => {
                buf.push_u8(1);
                buf.push_str(device_id.as_str());
            }
        }
        buf.push_u64(self.created_at.unix_seconds());
    }
}

impl SignedRecord for MembershipGenesis {
    const SIGN_LABEL: &'static str = labels::SIGN_MEMBERSHIP_GENESIS;

    fn signature(&self) -> &SignatureBytes {
        &self.signature
    }
}

impl MembershipGenesis {
    /// Verifies this membership record's signature against `public_key`.
    ///
    /// `MembershipGenesis` does not embed its signer's public key (see
    /// the "Project Genesis" section of
    /// `docs/protocol/keyit-protocol-v1.md`: this record accompanies a
    /// `ProjectGenesis`, whose `creator_device_public_identity` is the
    /// expected signer here), so the caller must supply it — typically
    /// the same key that verified the corresponding `ProjectGenesis`.
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

    fn sample_membership() -> MembershipGenesis {
        MembershipGenesis {
            project_id: ProjectId::new_unchecked_for_test("9e107d9d372bb682"),
            member_device_id: DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            role: Role::Owner,
            approved_by: ApprovalSource::Genesis,
            created_at: Timestamp::from_unix_seconds(1_755_878_400),
            signature: SignatureBytes::new_unchecked_for_test([0u8; 64]),
        }
    }

    #[test]
    fn constructs_with_expected_fields() {
        let membership = sample_membership();

        assert_eq!(membership.role, Role::Owner);
        assert_eq!(membership.approved_by, ApprovalSource::Genesis);
    }

    #[test]
    fn approval_source_can_reference_an_approving_device() {
        let approver = DeviceId::new_unchecked_for_test("d41d8cd98f00b205");
        let source = ApprovalSource::Device(approver.clone());
        assert_eq!(source, ApprovalSource::Device(approver));
    }

    #[test]
    fn canonical_preimage_excludes_signature() {
        let mut with_different_signature = sample_membership();
        with_different_signature.signature = SignatureBytes::new_unchecked_for_test([0xFFu8; 64]);

        let a = canonical_preimage(labels::SIGN_MEMBERSHIP_GENESIS, &sample_membership());
        let b = canonical_preimage(labels::SIGN_MEMBERSHIP_GENESIS, &with_different_signature);
        assert_eq!(a, b);
    }

    #[test]
    fn genesis_and_device_approval_sources_have_different_preimages() {
        let mut device_approved = sample_membership();
        device_approved.approved_by =
            ApprovalSource::Device(DeviceId::new_unchecked_for_test("d41d8cd98f00b205"));

        let a = canonical_preimage(labels::SIGN_MEMBERSHIP_GENESIS, &sample_membership());
        let b = canonical_preimage(labels::SIGN_MEMBERSHIP_GENESIS, &device_approved);
        assert_ne!(a, b);
    }

    #[test]
    fn signed_membership_verifies_against_the_correct_key() {
        let keypair = SigningKeyPair::generate();
        let mut membership = sample_membership();
        membership.signature = keypair.sign(labels::SIGN_MEMBERSHIP_GENESIS, &membership);

        membership
            .verify_signature(&keypair.public_key())
            .expect("a genuinely signed membership record should verify");
    }

    #[test]
    fn membership_signed_by_a_different_key_fails_verification() {
        let keypair = SigningKeyPair::generate();
        let other_keypair = SigningKeyPair::generate();
        let mut membership = sample_membership();
        membership.signature = keypair.sign(labels::SIGN_MEMBERSHIP_GENESIS, &membership);

        let err = membership
            .verify_signature(&other_keypair.public_key())
            .unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::SignatureVerificationFailed { .. }
        ));
    }
}
