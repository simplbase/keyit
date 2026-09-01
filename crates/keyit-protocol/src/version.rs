//! Protocol version representation.
//!
//! `docs/protocol/keyit-protocol-v1.md` refers to a `protocol_version`
//! field on several records. This type exists so that "which protocol
//! version" is a closed, typed choice
//! instead of an arbitrary `String` threaded through every record —
//! callers can't construct a `ProtocolVersion` that isn't one Keyit
//! actually knows about.

use std::fmt;
use std::str::FromStr;

use crate::error::ProtocolError;

/// A Keyit protocol version.
///
/// Currently only `V1` exists. The enum is `#[non_exhaustive]` so that
/// adding `V2` later is not a breaking change for code that already
/// matches on it exhaustively with a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProtocolVersion {
    /// Keyit Protocol v1, as recorded in
    /// `docs/protocol/keyit-protocol-v1.md`.
    V1,
}

impl ProtocolVersion {
    /// The protocol version this build of Keyit implements.
    pub const CURRENT: Self = Self::V1;

    /// The canonical string form of this version, as it will appear in
    /// signed protocol records once wire encoding is specified.
    ///
    /// `"keyit/1"` is a stable wire identifier: every already-signed
    /// record embeds this exact string, so changing it would break
    /// canonicalization and signature verification for every record
    /// signed under protocol v1.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::V1 => "keyit/1",
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProtocolVersion {
    type Err = ProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "keyit/1" => Ok(Self::V1),
            other => Err(ProtocolError::UnsupportedProtocolVersion(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_version_is_v1() {
        assert_eq!(ProtocolVersion::CURRENT, ProtocolVersion::V1);
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(ProtocolVersion::V1.to_string(), "keyit/1");
    }

    #[test]
    fn round_trips_through_parse() {
        let parsed: ProtocolVersion = "keyit/1".parse().expect("keyit/1 should parse");
        assert_eq!(parsed, ProtocolVersion::V1);
    }

    #[test]
    fn rejects_unknown_version_string() {
        let err = "keyit/99".parse::<ProtocolVersion>().unwrap_err();
        assert!(
            matches!(err, ProtocolError::UnsupportedProtocolVersion(found) if found == "keyit/99")
        );
    }
}
