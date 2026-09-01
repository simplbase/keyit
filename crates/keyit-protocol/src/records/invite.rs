use crate::canonical::{labels, CanonicalBytes, Canonicalize};
use crate::error::ProtocolError;
use crate::ids::{DeviceId, EnvironmentId, InviteId, ProjectId};
use crate::primitives::{NonceBytes, SignatureBytes, SigningPublicKeyBytes, Timestamp};
use crate::signing::SignedRecord;

/// Explicit lifecycle states an invite's creator (or an admin) can put it
/// in.
///
/// `docs/protocol/keyit-protocol-v1.md` gives an invite `expires_at` and
/// `max_uses` fields. This enum models explicit stored lifecycle state;
/// expiry and use-exhaustion can be computed from the invite fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InviteStatus {
    /// The invite has not been revoked. It may still be expired or
    /// exhausted by count; that is not represented by this status.
    Active,
    /// The creator (or an admin) explicitly revoked the invite before
    /// expiry.
    Revoked,
}

impl InviteStatus {
    /// Canonical string form, used in [`Invite`]'s
    /// [`Canonicalize`] implementation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

/// A signed invite: permission to request project membership, not
/// membership itself.
///
/// Conceptual record from the "Invite" section of
/// `docs/protocol/keyit-protocol-v1.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The invite's stable identifier.
    pub invite_id: InviteId,
    /// The project this invite grants join-request permission for.
    pub project_id: ProjectId,
    /// Environments a successful join request through this invite may
    /// ask to access. An empty list means project membership only.
    pub allowed_environment_ids: Vec<EnvironmentId>,
    /// The device that created this invite.
    pub created_by_device_id: DeviceId,
    /// Random material mixed into this invite's identifier derivation.
    ///
    /// Unlike a device, project, environment, or revision — each of which
    /// already has a field that varies per instance (a public key, a
    /// project-level genesis nonce plus creator/label, a revision's
    /// parent/payload hashes) — an invite's other fields
    /// (`project_id`, `created_by_device_id`, `created_at`) can collide
    /// across two distinct invites the same device creates for the same
    /// project in the same second. Without its own nonce, two such
    /// invites would derive the same `kvi_...` identifier. This field
    /// exists solely to make `InviteId` derivation collision-resistant.
    pub nonce: NonceBytes,
    /// When this invite stops being usable.
    pub expires_at: Timestamp,
    /// Maximum number of successful join requests this invite may
    /// produce.
    pub max_uses: u32,
    /// Current explicit status of this invite.
    pub status: InviteStatus,
    /// Signature over the rest of this record by the creating device.
    pub signature: SignatureBytes,
}

impl Canonicalize for Invite {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.invite_id.as_str());
        buf.push_str(self.project_id.as_str());
        buf.push_list(&self.allowed_environment_ids, |buf, id| {
            buf.push_str(id.as_str());
        });
        buf.push_str(self.created_by_device_id.as_str());
        buf.push_bytes(self.nonce.as_bytes());
        buf.push_u64(self.expires_at.unix_seconds());
        buf.push_u64(u64::from(self.max_uses));
        buf.push_str(self.status.as_str());
    }
}

impl SignedRecord for Invite {
    const SIGN_LABEL: &'static str = labels::SIGN_INVITE;

    fn signature(&self) -> &SignatureBytes {
        &self.signature
    }
}

impl Invite {
    /// Verifies this invite's signature against `public_key`.
    ///
    /// `Invite` does not embed `created_by_device_id`'s public key —
    /// the caller must supply it, typically looked up from that
    /// device's own [`crate::records::DeviceIdentity`].
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

    fn sample_invite() -> Invite {
        Invite {
            invite_id: InviteId::new_unchecked_for_test("c157a79031e1c40f"),
            project_id: ProjectId::new_unchecked_for_test("9e107d9d372bb682"),
            allowed_environment_ids: vec![EnvironmentId::new_unchecked_for_test(
                "e807f1fcf82d132f",
            )],
            created_by_device_id: DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            nonce: NonceBytes::new_unchecked_for_test(vec![6u8; 16]),
            expires_at: Timestamp::from_unix_seconds(1_755_882_000),
            max_uses: 1,
            status: InviteStatus::Active,
            signature: SignatureBytes::new_unchecked_for_test([0u8; 64]),
        }
    }

    #[test]
    fn constructs_with_expected_fields() {
        let invite = sample_invite();

        assert_eq!(invite.max_uses, 1);
        assert_eq!(invite.status, InviteStatus::Active);
        assert_eq!(invite.allowed_environment_ids.len(), 1);
    }

    #[test]
    fn invite_status_as_str_values_are_distinct() {
        assert_ne!(
            InviteStatus::Active.as_str(),
            InviteStatus::Revoked.as_str()
        );
    }

    #[test]
    fn canonical_preimage_excludes_signature() {
        let mut with_different_signature = sample_invite();
        with_different_signature.signature = SignatureBytes::new_unchecked_for_test([0xFFu8; 64]);

        let a = canonical_preimage(labels::SIGN_INVITE, &sample_invite());
        let b = canonical_preimage(labels::SIGN_INVITE, &with_different_signature);
        assert_eq!(a, b);
    }

    #[test]
    fn changing_status_changes_canonical_preimage() {
        let mut revoked = sample_invite();
        revoked.status = InviteStatus::Revoked;

        let a = canonical_preimage(labels::SIGN_INVITE, &sample_invite());
        let b = canonical_preimage(labels::SIGN_INVITE, &revoked);
        assert_ne!(a, b);
    }

    #[test]
    fn signed_invite_verifies_against_the_correct_key() {
        let keypair = SigningKeyPair::generate();
        let mut invite = sample_invite();
        invite.signature = keypair.sign(labels::SIGN_INVITE, &invite);

        invite
            .verify_signature(&keypair.public_key())
            .expect("a genuinely signed invite should verify");
    }

    #[test]
    fn invite_signed_by_a_different_key_fails_verification() {
        let keypair = SigningKeyPair::generate();
        let other_keypair = SigningKeyPair::generate();
        let mut invite = sample_invite();
        invite.signature = keypair.sign(labels::SIGN_INVITE, &invite);

        let err = invite
            .verify_signature(&other_keypair.public_key())
            .unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::SignatureVerificationFailed { .. }
        ));
    }
}
