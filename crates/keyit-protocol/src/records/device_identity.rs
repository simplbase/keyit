use crate::canonical::{CanonicalBytes, Canonicalize};
use crate::ids::DeviceId;
use crate::primitives::{PublicKeyBytes, SigningPublicKeyBytes, Timestamp};
use crate::version::ProtocolVersion;

/// A device's public protocol identity.
///
/// Conceptual record from the "Identity" section of
/// `docs/protocol/keyit-protocol-v1.md`. Holds only public key material:
/// private signing and key-agreement keys never leave the originating
/// device and have no representation in `keyit-protocol`.
///
/// Unlike every other record in this module, `DeviceIdentity` has no
/// `signature` field and is not a [`crate::signing::SignedRecord`]: its
/// authenticity is established by [`DeviceId`] derivation: the
/// identifier itself is a commitment to this exact key material, so a
/// separate signature over it would be redundant. This record still
/// implements [`Canonicalize`], under
/// [`crate::canonical::labels::SIGN_DEVICE_IDENTITY`], for completeness
/// and in case future work finds a use for its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// Protocol version this identity was created under.
    pub protocol_version: ProtocolVersion,
    /// This device's stable identifier.
    pub device_id: DeviceId,
    /// Ed25519 signing public key.
    pub signing_public_key: SigningPublicKeyBytes,
    /// X25519 key-agreement public key.
    pub encryption_public_key: PublicKeyBytes,
    /// When this identity was created, per the creating device's clock.
    pub created_at: Timestamp,
}

impl Canonicalize for DeviceIdentity {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.protocol_version.as_str());
        buf.push_str(self.device_id.as_str());
        buf.push_bytes(self.signing_public_key.as_bytes());
        buf.push_bytes(self.encryption_public_key.as_bytes());
        buf.push_u64(self.created_at.unix_seconds());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_preimage, labels};

    fn sample_identity() -> DeviceIdentity {
        DeviceIdentity {
            protocol_version: ProtocolVersion::CURRENT,
            device_id: DeviceId::new_unchecked_for_test("d41d8cd98f00b204"),
            signing_public_key: SigningPublicKeyBytes::new_unchecked_for_test([1u8; 32]),
            encryption_public_key: PublicKeyBytes::new_unchecked_for_test([2u8; 32]),
            created_at: Timestamp::from_unix_seconds(1_755_878_400),
        }
    }

    #[test]
    fn constructs_with_expected_fields() {
        let identity = sample_identity();

        assert_eq!(identity.protocol_version, ProtocolVersion::V1);
        assert_eq!(identity.signing_public_key.as_bytes().len(), 32);
        assert_eq!(identity.encryption_public_key.len(), 32);
        assert_ne!(
            identity.signing_public_key.as_bytes(),
            identity.encryption_public_key.as_bytes()
        );
    }

    #[test]
    fn canonical_preimage_is_deterministic() {
        let a = canonical_preimage(labels::SIGN_DEVICE_IDENTITY, &sample_identity());
        let b = canonical_preimage(labels::SIGN_DEVICE_IDENTITY, &sample_identity());
        assert_eq!(a, b);
    }

    #[test]
    fn changing_signing_public_key_changes_canonical_preimage() {
        let mut other = sample_identity();
        other.signing_public_key = SigningPublicKeyBytes::new_unchecked_for_test([9u8; 32]);

        let a = canonical_preimage(labels::SIGN_DEVICE_IDENTITY, &sample_identity());
        let b = canonical_preimage(labels::SIGN_DEVICE_IDENTITY, &other);
        assert_ne!(a, b);
    }
}
