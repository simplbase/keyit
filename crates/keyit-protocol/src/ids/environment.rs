use crate::canonical::{self, CanonicalBytes, Canonicalize};
use crate::ids::typed_id;
use crate::ids::DeviceId;
use crate::ids::ProjectId;
use crate::primitives::Timestamp;
use crate::version::ProtocolVersion;

typed_id!(
    /// Identifier for an environment within a project (`kve_...`).
    ///
    /// See the "Environment Model" section of
    /// `docs/protocol/keyit-protocol-v1.md`.
    EnvironmentId,
    "environment",
    "kve_"
);

/// Canonical preimage for [`EnvironmentId::derive`].
///
/// Fields: protocol version, project id, environment label, document
/// type, created at, created-by device id — matching
/// [`crate::records::EnvironmentGenesis`]'s identity-bearing fields.
///
/// `document_type` is taken as its canonical string form (e.g.
/// `"dotenv/v1"`, from [`crate::records::DocumentType::as_str`]) rather
/// than the `DocumentType` enum itself, so that `crate::ids` does not
/// need to depend on `crate::records` — callers pass
/// `document_type.as_str()`.
struct EnvironmentIdPreimage<'a> {
    protocol_version: ProtocolVersion,
    project_id: &'a ProjectId,
    environment_label: &'a str,
    document_type: &'a str,
    created_at: Timestamp,
    created_by_device_id: &'a DeviceId,
}

impl Canonicalize for EnvironmentIdPreimage<'_> {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.protocol_version.as_str());
        buf.push_str(self.project_id.as_str());
        buf.push_str(self.environment_label);
        buf.push_str(self.document_type);
        buf.push_u64(self.created_at.unix_seconds());
        buf.push_str(self.created_by_device_id.as_str());
    }
}

impl EnvironmentId {
    /// Derives an environment identifier from its genesis material.
    ///
    /// `document_type` is the document type's canonical string form
    /// (see [`crate::records::DocumentType::as_str`]).
    pub fn derive(
        protocol_version: ProtocolVersion,
        project_id: &ProjectId,
        environment_label: &str,
        document_type: &str,
        created_at: Timestamp,
        created_by_device_id: &DeviceId,
    ) -> Self {
        let preimage = EnvironmentIdPreimage {
            protocol_version,
            project_id,
            environment_label,
            document_type,
            created_at,
            created_by_device_id,
        };
        let hash = canonical::canonical_hash(canonical::labels::ENVIRONMENT_ID, &preimage);
        Self(format!(
            "{}{}",
            Self::PREFIX,
            crate::ids::encode_id_body(&hash)
        ))
    }
}

#[cfg(test)]
crate::ids::typed_id_tests!(
    EnvironmentId,
    "kve_",
    "xjjikfq3u3xnacc7we3yjts4sl3q5pbgrokp2zvkdvukgkeeebgq"
);

#[cfg(test)]
mod derive_tests {
    use super::*;

    fn sample_args() -> (ProjectId, DeviceId, Timestamp) {
        (
            ProjectId::new_unchecked_for_test("9e107d9d372bb682"),
            DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            Timestamp::from_unix_seconds(1_755_878_400),
        )
    }

    #[test]
    fn derivation_is_deterministic() {
        let (project, device, created_at) = sample_args();
        let a = EnvironmentId::derive(
            ProtocolVersion::CURRENT,
            &project,
            "development",
            "dotenv/v1",
            created_at,
            &device,
        );
        let b = EnvironmentId::derive(
            ProtocolVersion::CURRENT,
            &project,
            "development",
            "dotenv/v1",
            created_at,
            &device,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn derived_id_parses() {
        let (project, device, created_at) = sample_args();
        let id = EnvironmentId::derive(
            ProtocolVersion::CURRENT,
            &project,
            "development",
            "dotenv/v1",
            created_at,
            &device,
        );
        let reparsed = EnvironmentId::parse(id.as_str()).expect("derived id should parse");
        assert_eq!(reparsed, id);
    }

    #[test]
    fn different_environment_labels_derive_different_ids() {
        let (project, device, created_at) = sample_args();
        let a = EnvironmentId::derive(
            ProtocolVersion::CURRENT,
            &project,
            "development",
            "dotenv/v1",
            created_at,
            &device,
        );
        let b = EnvironmentId::derive(
            ProtocolVersion::CURRENT,
            &project,
            "production",
            "dotenv/v1",
            created_at,
            &device,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn different_projects_derive_different_ids() {
        let (project_a, device, created_at) = sample_args();
        let project_b = ProjectId::new_unchecked_for_test("differentprojectxyz");
        let a = EnvironmentId::derive(
            ProtocolVersion::CURRENT,
            &project_a,
            "development",
            "dotenv/v1",
            created_at,
            &device,
        );
        let b = EnvironmentId::derive(
            ProtocolVersion::CURRENT,
            &project_b,
            "development",
            "dotenv/v1",
            created_at,
            &device,
        );
        assert_ne!(a, b);
    }
}
