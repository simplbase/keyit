//! Keyit Protocol - core domain and protocol definitions.
//!
//! This crate is the shared foundation for the Keyit CLI and relay. It
//! owns identities, projects, environments, membership records,
//! canonical encoding, signing, encryption, revision history, and
//! synchronization semantics.
//!
//! # Modules
//!
//! - [`ids`] - typed, validated identifiers for devices, projects,
//!   environments, revisions, and invites.
//! - [`canonical`] - deterministic byte encoding used by identifier
//!   derivation and record signing.
//! - [`signing`] - Ed25519 signing and verification over canonical
//!   record preimages.
//! - [`encryption`] - X25519 key agreement, environment DEKs,
//!   AES-256-GCM payload encryption, and DEK wrapping for authorized
//!   devices.
//! - [`dotenv`] - `dotenv/v1` parsing and deterministic normalization.
//! - [`primitives`] - cryptographic and time value newtypes.
//! - [`records`] - protocol record structs such as `ProjectGenesis`,
//!   `EnvironmentGenesis`, `Invite`, `JoinRequest`, `Approval`,
//!   `Revision`, and `Revocation`.
//! - [`version`] - [`ProtocolVersion`], a closed type instead of a raw
//!   version string.
//! - [`error`] - [`ProtocolError`], the crate's error type.
//!
//! This crate performs no network operations and owns no process state.
//! The CLI and relay handle filesystem, HTTP, and operator-facing
//! concerns while this crate owns the stable protocol model.
//!
//! # Dependency direction
//!
//! `keyit-protocol` must never depend on `keyit-cli` or `keyit-relay`.
//! Presentation concerns (the CLI) and infrastructure concerns (the relay)
//! depend inward on this crate — never the reverse. This is enforced by
//! Cargo itself: neither `keyit-cli` nor `keyit-relay` appears in this
//! crate's `Cargo.toml`.

pub mod canonical;
pub mod dotenv;
pub mod encryption;
pub mod error;
pub mod ids;
pub mod primitives;
pub mod records;
pub mod signing;
pub mod version;

pub use error::ProtocolError;
pub use ids::{DeviceId, EnvironmentId, InviteId, ProjectId, RevisionId};
pub use version::ProtocolVersion;
