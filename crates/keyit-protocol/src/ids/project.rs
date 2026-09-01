use crate::canonical::{self, CanonicalBytes, Canonicalize};
use crate::ids::typed_id;
use crate::ids::DeviceId;
use crate::primitives::{NonceBytes, Timestamp};
use crate::version::ProtocolVersion;

typed_id!(
    /// Identifier for a Keyit project (`kvp_...`).
    ///
    /// See the "Project Genesis" section of
    /// `docs/protocol/keyit-protocol-v1.md`.
    ProjectId,
    "project",
    "kvp_"
);

/// Canonical preimage for [`ProjectId::derive`].
///
/// Fields: protocol version, genesis nonce, creator device id, created
/// at, project label, default relay URL — matching
/// [`crate::records::ProjectGenesis`]'s identity-bearing fields. The
/// genesis nonce is what makes two projects created by the same device
/// with the same label in the same second still derive distinct
/// `ProjectId`s.
struct ProjectIdPreimage<'a> {
    protocol_version: ProtocolVersion,
    genesis_nonce: &'a NonceBytes,
    creator_device_id: &'a DeviceId,
    created_at: Timestamp,
    project_label: &'a str,
    default_relay_url: &'a str,
}

impl Canonicalize for ProjectIdPreimage<'_> {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.protocol_version.as_str());
        buf.push_bytes(self.genesis_nonce.as_bytes());
        buf.push_str(self.creator_device_id.as_str());
        buf.push_u64(self.created_at.unix_seconds());
        buf.push_str(self.project_label);
        buf.push_str(self.default_relay_url);
    }
}

impl ProjectId {
    /// Derives a project identifier from its genesis material.
    #[allow(clippy::too_many_arguments)]
    pub fn derive(
        protocol_version: ProtocolVersion,
        genesis_nonce: &NonceBytes,
        creator_device_id: &DeviceId,
        created_at: Timestamp,
        project_label: &str,
        default_relay_url: &str,
    ) -> Self {
        let preimage = ProjectIdPreimage {
            protocol_version,
            genesis_nonce,
            creator_device_id,
            created_at,
            project_label,
            default_relay_url,
        };
        let hash = canonical::canonical_hash(canonical::labels::PROJECT_ID, &preimage);
        Self(format!(
            "{}{}",
            Self::PREFIX,
            crate::ids::encode_id_body(&hash)
        ))
    }
}

#[cfg(test)]
crate::ids::typed_id_tests!(
    ProjectId,
    "kvp_",
    "erbbbzeeg63fk2mau4betkmtngjuunjefebuz345ppjfhm57fqaq"
);

#[cfg(test)]
mod derive_tests {
    use super::*;

    fn sample_args() -> (NonceBytes, DeviceId, Timestamp, &'static str, &'static str) {
        (
            NonceBytes::new_unchecked_for_test(vec![7u8; 16]),
            DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            Timestamp::from_unix_seconds(1_755_878_400),
            "my-project",
            "wss://relay.example",
        )
    }

    #[test]
    fn derivation_is_deterministic() {
        let (nonce, creator, created_at, label, relay) = sample_args();
        let a = ProjectId::derive(
            ProtocolVersion::CURRENT,
            &nonce,
            &creator,
            created_at,
            label,
            relay,
        );
        let b = ProjectId::derive(
            ProtocolVersion::CURRENT,
            &nonce,
            &creator,
            created_at,
            label,
            relay,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn derived_id_parses() {
        let (nonce, creator, created_at, label, relay) = sample_args();
        let id = ProjectId::derive(
            ProtocolVersion::CURRENT,
            &nonce,
            &creator,
            created_at,
            label,
            relay,
        );
        let reparsed = ProjectId::parse(id.as_str()).expect("derived id should parse");
        assert_eq!(reparsed, id);
    }

    #[test]
    fn different_nonces_derive_different_ids() {
        let (_, creator, created_at, label, relay) = sample_args();
        let nonce_a = NonceBytes::new_unchecked_for_test(vec![7u8; 16]);
        let nonce_b = NonceBytes::new_unchecked_for_test(vec![9u8; 16]);
        let a = ProjectId::derive(
            ProtocolVersion::CURRENT,
            &nonce_a,
            &creator,
            created_at,
            label,
            relay,
        );
        let b = ProjectId::derive(
            ProtocolVersion::CURRENT,
            &nonce_b,
            &creator,
            created_at,
            label,
            relay,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn different_labels_derive_different_ids() {
        let (nonce, creator, created_at, _, relay) = sample_args();
        let a = ProjectId::derive(
            ProtocolVersion::CURRENT,
            &nonce,
            &creator,
            created_at,
            "label-a",
            relay,
        );
        let b = ProjectId::derive(
            ProtocolVersion::CURRENT,
            &nonce,
            &creator,
            created_at,
            "label-b",
            relay,
        );
        assert_ne!(a, b);
    }
}
