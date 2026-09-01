//! Core domain record structs for the Keyit protocol.
//!
//! Each type here is the typed Rust shape of one conceptual record from
//! `docs/protocol/keyit-protocol-v1.md`. Record structs hold public
//! metadata, hashes, public keys, nonces, and signatures; private keys,
//! unwrapped DEKs, and plaintext payloads are intentionally kept outside
//! records. Signing and verification are implemented through
//! [`crate::signing`], identifier/hash construction through
//! [`crate::canonical`], and payload encryption/DEK wrapping through
//! [`crate::encryption`].
//!
//! One module per record, named after the record, except an internal
//! `role` module holding the [`Role`] enum shared by
//! [`MembershipGenesis`] and [`Approval`].

mod approval;
mod device_identity;
mod environment_genesis;
mod invite;
mod join_request;
mod membership_genesis;
mod project_genesis;
mod revision;
mod revocation;
mod role;

pub use approval::Approval;
pub use device_identity::DeviceIdentity;
pub use environment_genesis::{DocumentType, EnvironmentGenesis};
pub use invite::{Invite, InviteStatus};
pub use join_request::JoinRequest;
pub use membership_genesis::{ApprovalSource, MembershipGenesis};
pub use project_genesis::ProjectGenesis;
pub use revision::Revision;
pub use revocation::Revocation;
pub use role::Role;
