use crate::canonical::{labels, CanonicalBytes, Canonicalize};
use crate::error::ProtocolError;
use crate::ids::{DeviceId, EnvironmentId, InviteId, ProjectId};
use crate::primitives::{PublicKeyBytes, SignatureBytes, SigningPublicKeyBytes, Timestamp};
use crate::signing::SignedRecord;

/// A device's signed request to join a project via an invite.
///
/// Conceptual record from the "Join" section of
/// `docs/protocol/keyit-protocol-v1.md`. Joining grants no access by
/// itself; see [`crate::records::Approval`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    /// The project being requested.
    pub project_id: ProjectId,
    /// The invite this request was made through.
    pub invite_id: InviteId,
    /// The joining device's stable identifier.
    pub joining_device_id: DeviceId,
    /// The joining device's signing public key, so `proof_signature` can
    /// be verified.
    pub joining_device_public_identity: SigningPublicKeyBytes,
    /// The joining device's X25519 public key, so authorized devices can
    /// wrap environment DEKs for this device after approval.
    pub joining_device_encryption_public_key: PublicKeyBytes,
    /// Environments this device is requesting access to.
    pub requested_environment_ids: Vec<EnvironmentId>,
    /// Untrusted human-readable device label.
    pub device_label: String,
    /// When this request was created.
    pub created_at: Timestamp,
    /// Signature proving control of the joining device's private signing
    /// key.
    pub proof_signature: SignatureBytes,
}

impl Canonicalize for JoinRequest {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.project_id.as_str());
        buf.push_str(self.invite_id.as_str());
        buf.push_str(self.joining_device_id.as_str());
        buf.push_bytes(self.joining_device_public_identity.as_bytes());
        buf.push_bytes(self.joining_device_encryption_public_key.as_bytes());
        buf.push_list(&self.requested_environment_ids, |buf, id| {
            buf.push_str(id.as_str());
        });
        buf.push_str(&self.device_label);
        buf.push_u64(self.created_at.unix_seconds());
    }
}

impl SignedRecord for JoinRequest {
    const SIGN_LABEL: &'static str = labels::SIGN_JOIN_REQUEST;

    fn signature(&self) -> &SignatureBytes {
        &self.proof_signature
    }
}

impl JoinRequest {
    /// Verifies this join request's `proof_signature` against its own
    /// embedded `joining_device_public_identity` — no external key
    /// lookup is needed, since (as with [`crate::records::ProjectGenesis`])
    /// the signer's public key travels with the record.
    ///
    /// This is exactly the cryptographic proof-of-possession the "Join"
    /// section of `docs/protocol/keyit-protocol-v1.md` describes: it
    /// proves the joining device controls the claimed signing key, and
    /// nothing more — it does not grant access (see
    /// [`crate::records::Approval`]).
    pub fn verify_signature(&self) -> Result<(), ProtocolError> {
        self.verify_signature_with(&self.joining_device_public_identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_preimage;
    use crate::signing::SigningKeyPair;

    fn sample_request() -> JoinRequest {
        JoinRequest {
            project_id: ProjectId::new_unchecked_for_test("9e107d9d372bb682"),
            invite_id: InviteId::new_unchecked_for_test("c157a79031e1c40f"),
            joining_device_id: DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            joining_device_public_identity: SigningPublicKeyBytes::new_unchecked_for_test(
                [1u8; 32],
            ),
            joining_device_encryption_public_key: PublicKeyBytes::new_unchecked_for_test([2u8; 32]),
            requested_environment_ids: vec![EnvironmentId::new_unchecked_for_test(
                "e807f1fcf82d132f",
            )],
            device_label: "Kiruthik MacBook".to_string(),
            created_at: Timestamp::from_unix_seconds(1_755_878_400),
            proof_signature: SignatureBytes::new_unchecked_for_test([0u8; 64]),
        }
    }

    #[test]
    fn constructs_with_expected_fields() {
        let request = sample_request();

        assert_eq!(request.device_label, "Kiruthik MacBook");
        assert_eq!(request.requested_environment_ids.len(), 1);
    }

    #[test]
    fn canonical_preimage_excludes_proof_signature() {
        let mut with_different_signature = sample_request();
        with_different_signature.proof_signature =
            SignatureBytes::new_unchecked_for_test([0xFFu8; 64]);

        let a = canonical_preimage(labels::SIGN_JOIN_REQUEST, &sample_request());
        let b = canonical_preimage(labels::SIGN_JOIN_REQUEST, &with_different_signature);
        assert_eq!(a, b);
    }

    #[test]
    fn changing_device_label_changes_canonical_preimage() {
        let mut other = sample_request();
        other.device_label = "different label".to_string();

        let a = canonical_preimage(labels::SIGN_JOIN_REQUEST, &sample_request());
        let b = canonical_preimage(labels::SIGN_JOIN_REQUEST, &other);
        assert_ne!(a, b);
    }

    #[test]
    fn signed_request_verifies_against_its_own_embedded_key() {
        let keypair = SigningKeyPair::generate();
        let mut request = sample_request();
        request.joining_device_public_identity = keypair.public_key();
        request.proof_signature = keypair.sign(labels::SIGN_JOIN_REQUEST, &request);

        request
            .verify_signature()
            .expect("a genuinely signed join request should verify");
    }

    #[test]
    fn tampered_request_fails_verification() {
        let keypair = SigningKeyPair::generate();
        let mut request = sample_request();
        request.joining_device_public_identity = keypair.public_key();
        request.proof_signature = keypair.sign(labels::SIGN_JOIN_REQUEST, &request);

        request.device_label = "tampered".to_string();

        let err = request.verify_signature().unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::SignatureVerificationFailed { .. }
        ));
    }
}
