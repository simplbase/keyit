//! Keyit CLI library.
//!
//! `crates/keyit-cli/src/main.rs` is a thin `clap`-based wrapper around
//! this crate: it parses arguments and prints results, but the actual
//! logic lives here so it can be tested through ordinary library
//! function calls instead of only by spawning the compiled binary.
//!
//! # Status
//!
//! `keyit-cli` implements local-first commands:
//!
//! - [`init::run_init`] — `keyit init`, which builds a real, signed,
//!   verified
//!   [`keyit_protocol::records::DeviceIdentity`]/
//!   [`keyit_protocol::records::ProjectGenesis`]/
//!   [`keyit_protocol::records::MembershipGenesis`] entirely through
//!   `keyit-protocol`'s existing identifier-derivation,
//!   canonicalization, and signing APIs, writes `keyit.toml` to the
//!   project repository, and writes runtime state to the Keyit data
//!   directory.
//! - [`environment::run_env_add`] — `keyit env add`, which creates a
//!   signed [`keyit_protocol::records::EnvironmentGenesis`] and local
//!   environment mapping.
//! - [`local_state::run_status`] and [`local_state::run_diff`] —
//!   `keyit status` and `keyit diff`, which inspect mapped local
//!   dotenv files without printing values. Diff compares against the
//!   latest local encrypted revision when one exists, otherwise against
//!   the empty prerevision baseline.
//! - [`inspect::run_whoami`], [`inspect::run_env_list`], and
//!   [`inspect::run_revision_list`] — `keyit whoami`,
//!   `keyit env list`, and `keyit revision list`, which report safe
//!   device, environment, and local encrypted revision metadata for
//!   recovery/support workflows.
//! - [`revision::run_push`] and [`revision::run_pull`] — encrypted
//!   revision creation and materialization. They use `keyit-protocol`
//!   encryption/key-wrapping primitives, wrap DEKs for active
//!   authorized devices, and can publish/fetch opaque encrypted bytes
//!   through a filesystem-backed relay directory or signed local HTTP
//!   relay URL.
//! - [`access::run_invite_create`], [`access::run_join`],
//!   [`access::run_approve`], and [`access::run_revoke`] — signed
//!   invite/join/approval/revocation access records.
//!
//! - [`access`] — local signed invite/join/approval/revocation
//!   orchestration.
//! - [`auth`] — effective local authorization reconstruction from
//!   genesis, join requests, approvals, and revocations.
//! - [`init`] — `keyit init`'s orchestration ([`init::run_init`],
//!   [`init::InitOptions`], [`init::InitOutcome`]).
//! - [`environment`] — `keyit env add`'s orchestration
//!   ([`environment::run_env_add`], [`environment::EnvAddOptions`],
//!   [`environment::EnvAddOutcome`]).
//! - [`local_state`] — local `status`/`diff` inspection
//!   ([`local_state::run_status`], [`local_state::run_diff`]).
//! - [`inspect`] — no-secret local recovery/support inspection
//!   ([`inspect::run_whoami`], [`inspect::run_env_list`],
//!   [`inspect::run_revision_list`]).
//! - [`revision`] — encrypted revision creation/materialization
//!   ([`revision::run_push`], [`revision::run_pull`]).
//! - [`device_key`] — the local device signing/encryption key store
//!   ([`device_key::load_or_create_device_signing_key`],
//!   [`device_key::load_or_create_device_encryption_key`],
//!   [`device_key::default_keyit_data_dir`]). Private keys live here,
//!   never inside any project repository.
//! - [`device_identity`] — builds this machine's `DeviceIdentity`,
//!   including its X25519 encryption public key.
//! - [`keyit_dir`] — the `keyit.toml` locator, runtime cache layout, and
//!   local TOML file formats.
//! - [`error`] — [`error::CliError`], this crate's error type.

pub mod access;
pub mod auth;
pub mod device_identity;
pub mod device_key;
pub mod environment;
pub mod error;
pub mod init;
pub mod inspect;
pub mod keyit_dir;
pub mod local_state;
pub mod project_state;
pub mod relay_client;
pub mod revision;
