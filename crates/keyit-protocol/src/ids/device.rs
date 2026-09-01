use crate::canonical::{self, CanonicalBytes, Canonicalize};
use crate::ids::typed_id;
use crate::primitives::{PublicKeyBytes, SigningPublicKeyBytes};
use crate::version::ProtocolVersion;

typed_id!(
    /// Identifier for a device identity (`kvd_...`).
    ///
    /// Device identities are the primary protocol actor; see the
    /// "Identity" section of `docs/protocol/keyit-protocol-v1.md`.
    DeviceId,
    "device",
    "kvd_"
);

/// Canonical preimage for [`DeviceId::derive`].
///
/// Fields: protocol version, signing public key, encryption public key —
/// the minimum subset of [`crate::records::DeviceIdentity`] that
/// identifies *this key material* rather than incidental metadata (a
/// device's `created_at`, for instance, says nothing about which device
/// it is).
struct DeviceIdPreimage<'a> {
    protocol_version: ProtocolVersion,
    signing_public_key: &'a SigningPublicKeyBytes,
    encryption_public_key: &'a PublicKeyBytes,
}

impl Canonicalize for DeviceIdPreimage<'_> {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.protocol_version.as_str());
        buf.push_bytes(self.signing_public_key.as_bytes());
        buf.push_bytes(self.encryption_public_key.as_bytes());
    }
}

impl DeviceId {
    /// Derives a device identifier from its key material.
    ///
    /// Two [`crate::records::DeviceIdentity`] records with the same
    /// signing and encryption public keys under the same protocol
    /// version always derive the same `DeviceId`; this is intentional —
    /// a device identity's stable identity *is* its key material.
    pub fn derive(
        protocol_version: ProtocolVersion,
        signing_public_key: &SigningPublicKeyBytes,
        encryption_public_key: &PublicKeyBytes,
    ) -> Self {
        let preimage = DeviceIdPreimage {
            protocol_version,
            signing_public_key,
            encryption_public_key,
        };
        let hash = canonical::canonical_hash(canonical::labels::DEVICE_ID, &preimage);
        Self(format!(
            "{}{}",
            Self::PREFIX,
            crate::ids::encode_id_body(&hash)
        ))
    }
}

#[cfg(test)]
crate::ids::typed_id_tests!(
    DeviceId,
    "kvd_",
    "ey5e3psbjch3q4quwabsgoo3xhymrwquyfw7z4jqqs7tyjks5ssq"
);

#[cfg(test)]
mod derive_tests {
    use super::*;

    fn sample_keys() -> (SigningPublicKeyBytes, PublicKeyBytes) {
        (
            SigningPublicKeyBytes::new_unchecked_for_test([1u8; 32]),
            PublicKeyBytes::new_unchecked_for_test([2u8; 32]),
        )
    }

    #[test]
    fn derivation_is_deterministic() {
        let (signing, encryption) = sample_keys();
        let a = DeviceId::derive(ProtocolVersion::CURRENT, &signing, &encryption);
        let b = DeviceId::derive(ProtocolVersion::CURRENT, &signing, &encryption);
        assert_eq!(a, b);
    }

    #[test]
    fn derived_id_parses() {
        let (signing, encryption) = sample_keys();
        let id = DeviceId::derive(ProtocolVersion::CURRENT, &signing, &encryption);
        let reparsed = DeviceId::parse(id.as_str()).expect("derived id should parse");
        assert_eq!(reparsed, id);
    }

    #[test]
    fn different_signing_keys_derive_different_ids() {
        let (_, encryption) = sample_keys();
        let signing_a = SigningPublicKeyBytes::new_unchecked_for_test([1u8; 32]);
        let signing_b = SigningPublicKeyBytes::new_unchecked_for_test([9u8; 32]);
        let a = DeviceId::derive(ProtocolVersion::CURRENT, &signing_a, &encryption);
        let b = DeviceId::derive(ProtocolVersion::CURRENT, &signing_b, &encryption);
        assert_ne!(a, b);
    }

    #[test]
    fn different_encryption_keys_derive_different_ids() {
        let (signing, _) = sample_keys();
        let encryption_a = PublicKeyBytes::new_unchecked_for_test([2u8; 32]);
        let encryption_b = PublicKeyBytes::new_unchecked_for_test([8u8; 32]);
        let a = DeviceId::derive(ProtocolVersion::CURRENT, &signing, &encryption_a);
        let b = DeviceId::derive(ProtocolVersion::CURRENT, &signing, &encryption_b);
        assert_ne!(a, b);
    }
}
