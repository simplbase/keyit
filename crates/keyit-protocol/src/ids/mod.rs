//! Typed protocol identifiers.
//!
//! `docs/protocol/keyit-protocol-v1.md` defines five namespaced
//! identifier prefixes (`kvd_`, `kvp_`, `kve_`, `kvr_`, `kvi_`).
//! The part after the prefix is lowercase RFC 4648 base32
//! (no padding) rendering of a 32-byte SHA-256 digest, which is always
//! exactly 52 characters. Each identifier type in this module validates
//! exactly that shape — namespace prefix, then a 52-character lowercase
//! base32 body — and derives real bodies from canonical record bytes via
//! [`crate::canonical`].
//!
//! All five types share one implementation via an internal `typed_id!`
//! macro so the validation, parsing, and display rules cannot drift
//! between namespaces.

mod device;
mod environment;
mod invite;
mod project;
mod revision;

pub use device::DeviceId;
pub use environment::EnvironmentId;
pub use invite::InviteId;
pub use project::ProjectId;
pub use revision::RevisionId;

use crate::error::ProtocolError;
use crate::primitives::HashBytes;

/// Exact length, in characters, of an identifier body (the part after the
/// namespace prefix).
///
/// A 32-byte SHA-256 digest, base32-encoded without padding, is always
/// `ceil(32 * 8 / 5) = 52` characters — base32 packs 5 bits per output
/// character, and 32 bytes is 256 bits.
const ID_BODY_LEN: usize = 52;

/// Whether `c` is a valid character of lowercase RFC 4648 base32 without
/// padding: `a`-`z` and `2`-`7`. (Base32's alphabet excludes `0`, `1`,
/// `8`, and `9` to avoid confusion with `o`/`i`/`b`/`g`.)
fn is_id_body_char(c: char) -> bool {
    c.is_ascii_lowercase() || matches!(c, '2'..='7')
}

/// Encodes a [`HashBytes`] digest as an identifier body: lowercase RFC
/// 4648 base32 without padding.
///
/// `data_encoding::BASE32_NOPAD` already emits uppercase output per RFC
/// 4648, so the result is lowercased explicitly.
pub(crate) fn encode_id_body(hash: &HashBytes) -> String {
    data_encoding::BASE32_NOPAD
        .encode(hash.as_bytes())
        .to_lowercase()
}

/// Validates an identifier body against the frozen shape: exactly
/// [`ID_BODY_LEN`] characters, each a valid lowercase base32 character.
fn validate_body(namespace: &'static str, body: &str) -> Result<(), ProtocolError> {
    if body.is_empty() {
        return Err(ProtocolError::InvalidIdentifier {
            namespace,
            reason: "identifier body is empty".to_string(),
        });
    }
    if body.len() != ID_BODY_LEN {
        return Err(ProtocolError::InvalidIdentifier {
            namespace,
            reason: format!(
                "identifier body \"{body}\" has length {}, expected exactly {ID_BODY_LEN}",
                body.len()
            ),
        });
    }
    if let Some(bad_char) = body.chars().find(|c| !is_id_body_char(*c)) {
        return Err(ProtocolError::InvalidIdentifier {
            namespace,
            reason: format!(
                "identifier body \"{body}\" contains disallowed character '{bad_char}'; only lowercase base32 characters (a-z, 2-7) are allowed"
            ),
        });
    }
    Ok(())
}

/// Strips `expected_prefix` (e.g. `"kvd_"`) off `raw`, returning the
/// remaining body or a namespace error if the prefix does not match.
fn split_prefix<'a>(
    namespace: &'static str,
    expected_prefix: &'static str,
    raw: &'a str,
) -> Result<&'a str, ProtocolError> {
    raw.strip_prefix(expected_prefix)
        .ok_or_else(|| ProtocolError::InvalidNamespace {
            namespace,
            expected_prefix,
            found: raw.to_string(),
        })
}

/// Defines a newtype identifier for one Keyit namespace.
///
/// Generates:
/// - the struct itself, wrapping the full `prefix_body` string
/// - `NAMESPACE` / `PREFIX` associated constants
/// - `parse` / `FromStr` (validates namespace prefix and body shape)
/// - `Display` (renders the full `prefix_body` string)
/// - manual `Debug` (same output as `Display`, satisfies the workspace's
///   `missing_debug_implementations` lint without printing a redundant
///   tuple wrapper)
/// - `as_str`
/// - `new_unchecked_for_test`, gated to test builds (or the `test-util`
///   feature for use from other crates' tests), documented as a
///   placeholder until real identifier derivation exists
macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident, $namespace:literal, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// Human-readable namespace name, used in error messages.
            pub const NAMESPACE: &'static str = $namespace;
            /// The namespace prefix this identifier must start with.
            pub const PREFIX: &'static str = $prefix;

            /// Parses and validates a full identifier string (prefix +
            /// body).
            pub fn parse(raw: &str) -> Result<Self, crate::error::ProtocolError> {
                let body = crate::ids::split_prefix(Self::NAMESPACE, Self::PREFIX, raw)?;
                crate::ids::validate_body(Self::NAMESPACE, body)?;
                Ok(Self(raw.to_string()))
            }

            /// Builds an identifier from a body string without
            /// validation, for use in tests only.
            ///
            /// Production identifiers are derived from canonical protocol
            /// record bytes, not arbitrary body strings. This constructor
            /// intentionally performs no validation so tests can exercise
            /// malformed or edge-case bodies too.
            #[cfg(any(test, feature = "test-util"))]
            pub fn new_unchecked_for_test(body: &str) -> Self {
                Self(format!("{}{}", Self::PREFIX, body))
            }

            /// Borrows the full `prefix_body` identifier string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::str::FromStr for $name {
            type Err = crate::error::ProtocolError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
    };
}

/// Generates a standard suite of parsing/validation tests for a
/// [`typed_id!`] type, so the five namespaces are tested identically
/// instead of by hand-copied test functions that can drift apart.
#[cfg(test)]
macro_rules! typed_id_tests {
    ($name:ident, $prefix:literal, $sample_body:literal) => {
        #[cfg(test)]
        mod tests {
            use super::$name;
            use crate::error::ProtocolError;

            const SAMPLE_BODY: &str = $sample_body;

            #[test]
            fn sample_body_has_expected_shape() {
                // Sanity check on the fixture itself: if this fails, every
                // other test below is exercising the wrong body shape.
                assert_eq!(SAMPLE_BODY.len(), crate::ids::ID_BODY_LEN);
                assert!(SAMPLE_BODY.chars().all(crate::ids::is_id_body_char));
            }

            #[test]
            fn parses_valid_identifier() {
                let raw = format!("{}{}", $prefix, SAMPLE_BODY);
                let id = $name::parse(&raw).expect("valid id should parse");
                assert_eq!(id.as_str(), raw);
            }

            #[test]
            fn rejects_wrong_namespace_prefix() {
                let raw = format!("kvx_{}", SAMPLE_BODY);
                let err = $name::parse(&raw).unwrap_err();
                assert!(matches!(err, ProtocolError::InvalidNamespace { .. }));
            }

            #[test]
            fn rejects_missing_prefix_entirely() {
                let err = $name::parse(SAMPLE_BODY).unwrap_err();
                assert!(matches!(err, ProtocolError::InvalidNamespace { .. }));
            }

            #[test]
            fn rejects_malformed_body_characters() {
                let mut body = SAMPLE_BODY.to_string();
                body.replace_range(0..1, "!");
                let raw = format!("{}{}", $prefix, body);
                let err = $name::parse(&raw).unwrap_err();
                assert!(matches!(err, ProtocolError::InvalidIdentifier { .. }));
            }

            #[test]
            fn rejects_empty_body() {
                let err = $name::parse($prefix).unwrap_err();
                assert!(matches!(err, ProtocolError::InvalidIdentifier { .. }));
            }

            #[test]
            fn rejects_body_shorter_than_expected_length() {
                let short = &SAMPLE_BODY[..SAMPLE_BODY.len() - 1];
                let raw = format!("{}{}", $prefix, short);
                let err = $name::parse(&raw).unwrap_err();
                assert!(matches!(err, ProtocolError::InvalidIdentifier { .. }));
            }

            #[test]
            fn rejects_body_longer_than_expected_length() {
                let long = format!("{}{}", SAMPLE_BODY, "a");
                let raw = format!("{}{}", $prefix, long);
                let err = $name::parse(&raw).unwrap_err();
                assert!(matches!(err, ProtocolError::InvalidIdentifier { .. }));
            }

            #[test]
            fn rejects_uppercase_body() {
                let raw = format!("{}{}", $prefix, SAMPLE_BODY.to_uppercase());
                let err = $name::parse(&raw).unwrap_err();
                assert!(matches!(err, ProtocolError::InvalidIdentifier { .. }));
            }

            #[test]
            fn rejects_padded_body() {
                let mut body = SAMPLE_BODY[..SAMPLE_BODY.len() - 1].to_string();
                body.push('=');
                let raw = format!("{}{}", $prefix, body);
                let err = $name::parse(&raw).unwrap_err();
                assert!(matches!(err, ProtocolError::InvalidIdentifier { .. }));
            }

            #[test]
            fn rejects_digits_outside_base32_alphabet() {
                // '9' is not part of RFC 4648 base32's alphabet (0, 1, 8, 9
                // are excluded to avoid visual confusion with o/i/b/g).
                let mut body = SAMPLE_BODY[..SAMPLE_BODY.len() - 1].to_string();
                body.push('9');
                let raw = format!("{}{}", $prefix, body);
                let err = $name::parse(&raw).unwrap_err();
                assert!(matches!(err, ProtocolError::InvalidIdentifier { .. }));
            }

            #[test]
            fn display_round_trips_through_parse() {
                let raw = format!("{}{}", $prefix, SAMPLE_BODY);
                let id = $name::parse(&raw).expect("valid id should parse");
                let rendered = id.to_string();
                assert_eq!(rendered, raw);
                let reparsed: $name = rendered.parse().expect("rendered id should reparse");
                assert_eq!(reparsed, id);
            }

            #[test]
            fn new_unchecked_for_test_builds_expected_string() {
                let id = $name::new_unchecked_for_test(SAMPLE_BODY);
                assert_eq!(id.as_str(), format!("{}{}", $prefix, SAMPLE_BODY));
            }
        }
    };
}

pub(crate) use typed_id;
#[cfg(test)]
pub(crate) use typed_id_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_id_body_has_expected_length() {
        let hash = HashBytes::new_unchecked_for_test([0u8; 32]);
        assert_eq!(encode_id_body(&hash).len(), ID_BODY_LEN);
    }

    #[test]
    fn encoded_id_body_is_lowercase() {
        let hash = HashBytes::new_unchecked_for_test([0xFFu8; 32]);
        let body = encode_id_body(&hash);
        assert_eq!(body, body.to_lowercase());
    }

    #[test]
    fn encoded_id_body_uses_only_valid_characters() {
        let hash = HashBytes::new_unchecked_for_test([0xAAu8; 32]);
        let body = encode_id_body(&hash);
        assert!(body.chars().all(is_id_body_char));
    }

    #[test]
    fn different_hashes_encode_to_different_bodies() {
        let a = encode_id_body(&HashBytes::new_unchecked_for_test([1u8; 32]));
        let b = encode_id_body(&HashBytes::new_unchecked_for_test([2u8; 32]));
        assert_ne!(a, b);
    }
}
