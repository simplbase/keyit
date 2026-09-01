//! Builds this machine's [`DeviceIdentity`] from its local device keys.
//!
//! `DeviceIdentity` needs both an Ed25519 signing public key (real, from
//! [`crate::device_key`]) and an X25519 encryption public key (real,
//! from [`keyit_protocol::encryption::KeyAgreementKeyPair`]).

use keyit_protocol::encryption::KeyAgreementKeyPair;
use keyit_protocol::ids::DeviceId;
use keyit_protocol::primitives::Timestamp;
use keyit_protocol::records::DeviceIdentity;
use keyit_protocol::signing::SigningKeyPair;
use keyit_protocol::version::ProtocolVersion;

/// Builds this machine's [`DeviceIdentity`] from its already
/// loaded/generated signing and encryption keypairs.
pub fn build_device_identity(
    signing_keypair: &SigningKeyPair,
    encryption_keypair: &KeyAgreementKeyPair,
    created_at: Timestamp,
) -> DeviceIdentity {
    let signing_public_key = signing_keypair.public_key();
    let encryption_public_key = encryption_keypair.public_key();
    let device_id = DeviceId::derive(
        ProtocolVersion::CURRENT,
        &signing_public_key,
        &encryption_public_key,
    );

    DeviceIdentity {
        protocol_version: ProtocolVersion::CURRENT,
        device_id,
        signing_public_key,
        encryption_public_key,
        created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_device_identity_produces_a_stable_device_id_for_the_same_keys() {
        let signing_keypair = SigningKeyPair::generate();
        let encryption_keypair = KeyAgreementKeyPair::generate();
        let created_at = Timestamp::from_unix_seconds(1_755_878_400);

        let a = build_device_identity(&signing_keypair, &encryption_keypair, created_at);
        let b = build_device_identity(&signing_keypair, &encryption_keypair, created_at);

        assert_eq!(a.device_id, b.device_id);
    }

    #[test]
    fn different_encryption_keys_produce_different_device_ids() {
        let signing_keypair = SigningKeyPair::generate();
        let encryption_a = KeyAgreementKeyPair::generate();
        let encryption_b = KeyAgreementKeyPair::generate();
        let created_at = Timestamp::from_unix_seconds(1_755_878_400);

        let a = build_device_identity(&signing_keypair, &encryption_a, created_at);
        let b = build_device_identity(&signing_keypair, &encryption_b, created_at);

        assert_ne!(a.device_id, b.device_id);
    }
}
