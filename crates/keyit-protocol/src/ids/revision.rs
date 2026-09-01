use crate::canonical::{self, CanonicalBytes, Canonicalize};
use crate::ids::typed_id;
use crate::ids::DeviceId;
use crate::ids::EnvironmentId;
use crate::ids::ProjectId;
use crate::primitives::{HashBytes, Timestamp};

typed_id!(
    /// Identifier for a single environment revision (`kvr_...`).
    ///
    /// See the "Revision Chain" section of
    /// `docs/protocol/keyit-protocol-v1.md`.
    RevisionId,
    "revision",
    "kvr_"
);

/// Canonical preimage for [`RevisionId::derive`].
///
/// Fields: project id, environment id, parent revision hash, payload
/// hash, author device id, created at — matching
/// [`crate::records::Revision`]'s identity-bearing fields.
///
/// This derivation uses only the parent's *hash*
/// (`parent_revision_hash: Option<&HashBytes>`), not its `RevisionId`,
/// because the hash is what actually chains one revision to the exact
/// bytes of its parent — a `RevisionId` is itself derived from that same
/// hash (transitively), so including both would be redundant rather than
/// safer. `None` (the chain's first revision) and `Some` are encoded
/// distinguishably via [`CanonicalBytes::push_opt_bytes`].
struct RevisionIdPreimage<'a> {
    project_id: &'a ProjectId,
    environment_id: &'a EnvironmentId,
    parent_revision_hash: Option<&'a HashBytes>,
    payload_hash: &'a HashBytes,
    author_device_id: &'a DeviceId,
    created_at: Timestamp,
}

impl Canonicalize for RevisionIdPreimage<'_> {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.project_id.as_str());
        buf.push_str(self.environment_id.as_str());
        buf.push_opt_bytes(self.parent_revision_hash.map(HashBytes::as_bytes));
        buf.push_bytes(self.payload_hash.as_bytes());
        buf.push_str(self.author_device_id.as_str());
        buf.push_u64(self.created_at.unix_seconds());
    }
}

impl RevisionId {
    /// Derives a revision identifier from its chain-linking material.
    pub fn derive(
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
        parent_revision_hash: Option<&HashBytes>,
        payload_hash: &HashBytes,
        author_device_id: &DeviceId,
        created_at: Timestamp,
    ) -> Self {
        let preimage = RevisionIdPreimage {
            project_id,
            environment_id,
            parent_revision_hash,
            payload_hash,
            author_device_id,
            created_at,
        };
        let hash = canonical::canonical_hash(canonical::labels::REVISION_ID, &preimage);
        Self(format!(
            "{}{}",
            Self::PREFIX,
            crate::ids::encode_id_body(&hash)
        ))
    }
}

#[cfg(test)]
crate::ids::typed_id_tests!(
    RevisionId,
    "kvr_",
    "fmqu3xzteyawkgnpzmti6y3choalsgtfezjhozuojuba3b65sb4a"
);

#[cfg(test)]
mod derive_tests {
    use super::*;

    fn sample_args() -> (ProjectId, EnvironmentId, HashBytes, DeviceId, Timestamp) {
        (
            ProjectId::new_unchecked_for_test("9e107d9d372bb682"),
            EnvironmentId::new_unchecked_for_test("e807f1fcf82d132f"),
            HashBytes::new_unchecked_for_test([5u8; 32]),
            DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            Timestamp::from_unix_seconds(1_755_878_400),
        )
    }

    #[test]
    fn derivation_is_deterministic() {
        let (project, environment, payload_hash, author, created_at) = sample_args();
        let a = RevisionId::derive(
            &project,
            &environment,
            None,
            &payload_hash,
            &author,
            created_at,
        );
        let b = RevisionId::derive(
            &project,
            &environment,
            None,
            &payload_hash,
            &author,
            created_at,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn derived_id_parses() {
        let (project, environment, payload_hash, author, created_at) = sample_args();
        let id = RevisionId::derive(
            &project,
            &environment,
            None,
            &payload_hash,
            &author,
            created_at,
        );
        let reparsed = RevisionId::parse(id.as_str()).expect("derived id should parse");
        assert_eq!(reparsed, id);
    }

    #[test]
    fn root_and_non_root_revisions_derive_different_ids() {
        let (project, environment, payload_hash, author, created_at) = sample_args();
        let parent_hash = HashBytes::new_unchecked_for_test([4u8; 32]);
        let root = RevisionId::derive(
            &project,
            &environment,
            None,
            &payload_hash,
            &author,
            created_at,
        );
        let non_root = RevisionId::derive(
            &project,
            &environment,
            Some(&parent_hash),
            &payload_hash,
            &author,
            created_at,
        );
        assert_ne!(root, non_root);
    }

    #[test]
    fn different_payload_hashes_derive_different_ids() {
        let (project, environment, _, author, created_at) = sample_args();
        let payload_a = HashBytes::new_unchecked_for_test([5u8; 32]);
        let payload_b = HashBytes::new_unchecked_for_test([6u8; 32]);
        let a = RevisionId::derive(
            &project,
            &environment,
            None,
            &payload_a,
            &author,
            created_at,
        );
        let b = RevisionId::derive(
            &project,
            &environment,
            None,
            &payload_b,
            &author,
            created_at,
        );
        assert_ne!(a, b);
    }
}
