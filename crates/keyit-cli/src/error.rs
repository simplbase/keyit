//! The CLI crate's error type.
//!
//! Kept as a single flat enum with a hand-written `Display` impl, no
//! `thiserror`/`anyhow` — the same choice `keyit-protocol::error` makes,
//! for the same reason: the surface area is still small enough that a
//! plain `enum` is easy to match on in tests and does not add a
//! dependency.

use std::fmt;
use std::path::PathBuf;

/// Errors produced by `keyit-cli`'s library code.
#[derive(Debug)]
pub enum CliError {
    /// A filesystem operation failed.
    Io {
        /// The path the operation was acting on.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// A `keyit-protocol` operation failed (record construction, or —
    /// most importantly — signature verification of a record `keyit
    /// init` just built, before it is written to disk).
    Protocol(keyit_protocol::ProtocolError),
    /// A relay storage operation failed.
    Relay(keyit_relay::RelayStoreError),
    /// A relay HTTP operation failed.
    RelayHttp {
        /// Human-readable reason for diagnostics.
        reason: String,
    },
    /// `keyit init` was run in a directory that already has a
    /// `.keyit/project.toml`, and `--force` was not passed.
    AlreadyInitialized {
        /// The `.keyit/` directory that already contains project
        /// metadata.
        path: PathBuf,
    },
    /// A command requiring an initialized Keyit project was run before
    /// `keyit init`.
    NotInitialized {
        /// The expected project metadata path.
        path: PathBuf,
    },
    /// `keyit env add` was asked to create an environment label that is
    /// already present in this project.
    EnvironmentAlreadyExists {
        /// The duplicate environment label.
        label: String,
    },
    /// An environment selector did not match any stored environment ID
    /// or label.
    EnvironmentNotFound {
        /// The selector the user passed.
        selector: String,
    },
    /// A command expected at least one local encrypted revision for an
    /// environment, but none has been created yet.
    NoLocalRevision {
        /// Environment label or ID used for diagnostics.
        environment: String,
    },
    /// A push attempted to build on a stale local or relay revision.
    RevisionConflict {
        /// Human-readable reason for diagnostics.
        reason: String,
    },
    /// A pull would replace local dotenv edits that do not match the
    /// currently materialized revision.
    PullWouldOverwriteLocalChanges {
        /// The local dotenv path that would be overwritten.
        path: PathBuf,
    },
    /// The local device key does not match the project creator/owner
    /// membership record. Only the genesis owner device can create
    /// environments.
    NotProjectOwner {
        /// Human-readable reason for diagnostics.
        reason: String,
    },
    /// An invite or join request failed access-flow validation.
    InviteNotUsable {
        /// Human-readable reason for diagnostics.
        reason: String,
    },
    /// The local Keyit data directory could not be resolved because no
    /// `HOME` (or `KEYIT_DATA_DIR`/`XDG_DATA_HOME`) environment variable
    /// is set.
    HomeDirectoryNotFound,
    /// The local device signing key file exists but its contents are not
    /// a valid 32-byte hex-encoded Ed25519 seed.
    MalformedDeviceKey {
        /// The file that failed to parse.
        path: PathBuf,
    },
    /// The configured native key store could not be used.
    KeyStoreUnavailable {
        /// Human-readable reason for diagnostics.
        reason: String,
    },
    /// A `.keyit/` metadata file exists but could not be parsed back into
    /// the record it is supposed to represent.
    MalformedRecordFile {
        /// The file that failed to parse.
        path: PathBuf,
        /// Why it was rejected.
        reason: String,
    },
    /// A `.keyit/` metadata file could not be encoded as TOML.
    ///
    /// Not expected to occur in practice — the values `keyit-cli` writes
    /// are all plain strings/integers — but `toml::to_string_pretty` is
    /// fallible, so this variant exists rather than panicking.
    TomlEncode {
        /// The file that failed to encode.
        path: PathBuf,
        /// The underlying encoding error, rendered to a string.
        reason: String,
    },
}

impl CliError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "I/O error at \"{}\": {source}", path.display())
            }
            Self::Protocol(err) => write!(f, "{err}"),
            Self::Relay(err) => write!(f, "{err}"),
            Self::RelayHttp { reason } => write!(f, "relay HTTP error: {reason}"),
            Self::AlreadyInitialized { path } => write!(
                f,
                "\"{}\" already contains a Keyit project (found project.toml); pass --force to overwrite the existing Keyit-generated metadata",
                path.display()
            ),
            Self::NotInitialized { path } => write!(
                f,
                "\"{}\" was not found; run `keyit init` before this command",
                path.display()
            ),
            Self::EnvironmentAlreadyExists { label } => {
                write!(f, "environment \"{label}\" already exists in this Keyit project")
            }
            Self::EnvironmentNotFound { selector } => {
                write!(f, "environment \"{selector}\" was not found in this Keyit project")
            }
            Self::NoLocalRevision { environment } => {
                write!(
                    f,
                    "environment \"{environment}\" has no local encrypted revisions yet"
                )
            }
            Self::RevisionConflict { reason } => {
                write!(f, "revision conflict: {reason}")
            }
            Self::PullWouldOverwriteLocalChanges { path } => write!(
                f,
                "pull would overwrite local changes at \"{}\"; rerun with --force to replace the file",
                path.display()
            ),
            Self::NotProjectOwner { reason } => {
                write!(f, "this device cannot modify the Keyit project yet: {reason}")
            }
            Self::InviteNotUsable { reason } => {
                write!(f, "invite cannot be used: {reason}")
            }
            Self::HomeDirectoryNotFound => write!(
                f,
                "could not determine where to store the local Keyit device key: set KEYIT_DATA_DIR, XDG_DATA_HOME, or HOME"
            ),
            Self::MalformedDeviceKey { path } => write!(
                f,
                "\"{}\" does not contain a valid 32-byte hex-encoded device signing key",
                path.display()
            ),
            Self::KeyStoreUnavailable { reason } => {
                write!(f, "native key store is unavailable: {reason}")
            }
            Self::MalformedRecordFile { path, reason } => {
                write!(f, "\"{}\" is not a valid Keyit record file: {reason}", path.display())
            }
            Self::TomlEncode { path, reason } => {
                write!(f, "failed to encode \"{}\" as TOML: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Protocol(err) => Some(err),
            Self::Relay(err) => Some(err),
            _ => None,
        }
    }
}

impl From<keyit_protocol::ProtocolError> for CliError {
    fn from(err: keyit_protocol::ProtocolError) -> Self {
        Self::Protocol(err)
    }
}

impl From<keyit_relay::RelayStoreError> for CliError {
    fn from(err: keyit_relay::RelayStoreError) -> Self {
        Self::Relay(err)
    }
}
