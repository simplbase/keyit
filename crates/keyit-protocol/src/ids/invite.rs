use crate::canonical::{self, CanonicalBytes, Canonicalize};
use crate::ids::typed_id;
use crate::ids::DeviceId;
use crate::ids::ProjectId;
use crate::primitives::{NonceBytes, Timestamp};

typed_id!(
    /// Identifier for a project invite (`kvi_...`).
    ///
    /// See the "Invite" section of `docs/protocol/keyit-protocol-v1.md`.
    InviteId,
    "invite",
    "kvi_"
);

/// Canonical preimage for [`InviteId::derive`].
///
/// Fields: project id, created-by device id, nonce, created at —
/// matching [`crate::records::Invite`]'s identity-bearing fields. The
/// nonce (see [`crate::records::Invite::nonce`]) is required here: none
/// of the other fields are guaranteed to differ between two invites the
/// same device creates for the same project within the same second, so
/// without it, two distinct invites could derive the same `InviteId`.
struct InviteIdPreimage<'a> {
    project_id: &'a ProjectId,
    created_by_device_id: &'a DeviceId,
    nonce: &'a NonceBytes,
    created_at: Timestamp,
}

impl Canonicalize for InviteIdPreimage<'_> {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.project_id.as_str());
        buf.push_str(self.created_by_device_id.as_str());
        buf.push_bytes(self.nonce.as_bytes());
        buf.push_u64(self.created_at.unix_seconds());
    }
}

impl InviteId {
    /// Derives an invite identifier from its creation material.
    pub fn derive(
        project_id: &ProjectId,
        created_by_device_id: &DeviceId,
        nonce: &NonceBytes,
        created_at: Timestamp,
    ) -> Self {
        let preimage = InviteIdPreimage {
            project_id,
            created_by_device_id,
            nonce,
            created_at,
        };
        let hash = canonical::canonical_hash(canonical::labels::INVITE_ID, &preimage);
        Self(format!(
            "{}{}",
            Self::PREFIX,
            crate::ids::encode_id_body(&hash)
        ))
    }
}

#[cfg(test)]
crate::ids::typed_id_tests!(
    InviteId,
    "kvi_",
    "kakptlz2nbh52zfhoxa4jrjs5ztldolmwvvr2aqxburetntwj52q"
);

#[cfg(test)]
mod derive_tests {
    use super::*;

    fn sample_args() -> (ProjectId, DeviceId, NonceBytes, Timestamp) {
        (
            ProjectId::new_unchecked_for_test("9e107d9d372bb682"),
            DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            NonceBytes::new_unchecked_for_test(vec![6u8; 16]),
            Timestamp::from_unix_seconds(1_755_882_000),
        )
    }

    #[test]
    fn derivation_is_deterministic() {
        let (project, device, nonce, created_at) = sample_args();
        let a = InviteId::derive(&project, &device, &nonce, created_at);
        let b = InviteId::derive(&project, &device, &nonce, created_at);
        assert_eq!(a, b);
    }

    #[test]
    fn derived_id_parses() {
        let (project, device, nonce, created_at) = sample_args();
        let id = InviteId::derive(&project, &device, &nonce, created_at);
        let reparsed = InviteId::parse(id.as_str()).expect("derived id should parse");
        assert_eq!(reparsed, id);
    }

    #[test]
    fn different_nonces_derive_different_ids_for_otherwise_identical_invites() {
        let (project, device, _, created_at) = sample_args();
        let nonce_a = NonceBytes::new_unchecked_for_test(vec![6u8; 16]);
        let nonce_b = NonceBytes::new_unchecked_for_test(vec![11u8; 16]);
        let a = InviteId::derive(&project, &device, &nonce_a, created_at);
        let b = InviteId::derive(&project, &device, &nonce_b, created_at);
        assert_ne!(a, b);
    }
}
