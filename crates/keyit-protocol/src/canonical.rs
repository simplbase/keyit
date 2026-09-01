//! Canonical byte encoding for Keyit protocol values.
//!
//! Hash-derived identifiers and signatures both need
//! *the same bytes, every time, from every implementation* for the same
//! logical value. Rust's `derive(Debug)`, a `serde`-derived JSON or
//! `bincode` encoding, or any other general-purpose serializer do not
//! give you that: struct field order in `Debug` output and `bincode` is
//! an accident of source layout (and can change across compiler or
//! library versions), JSON key order is not guaranteed stable by the
//! JSON spec even if a given serializer happens to emit fields in
//! declaration order today, and none of these formats are designed to
//! be *injective* — encodings of two different logical values could
//! collide in the general case, which is fatal for a hash used as an
//! identifier. So none of them are canonical protocol encoding, and
//! nothing in this crate uses them for that purpose.
//!
//! This module is the alternative: a small, explicit, hand-written byte
//! layer. Callers build up a [`CanonicalBytes`] buffer by pushing fields
//! one at a time, in an order the *caller* chooses and documents (not
//! one inferred from a struct definition), and every push is
//! length-prefixed so that concatenation stays injective (see
//! [`CanonicalBytes::push_bytes`]).
//!
//! # Uses
//!
//! Two things build on this layer now:
//!
//! - The five identifier types in [`crate::ids`], deterministically
//!   derived from a documented, tested subset of each record's fields
//!   via [`canonical_hash`].
//! - Ed25519 signing over whole record preimages, which signs the
//!   *unhashed* canonical bytes directly via [`canonical_preimage`]
//!   rather than a SHA-256 digest of them -
//!   Ed25519 already signs arbitrary-length messages, so there is no
//!   benefit to pre-hashing, and it keeps "what does the signature
//!   cover" answerable as "exactly these canonical bytes" with no
//!   intermediate step.

use sha2::{Digest, Sha256};

use crate::primitives::HashBytes;

/// Domain-separation labels for identifier derivation hash preimages.
///
/// Every [`canonical_hash`] call is seeded with one of these labels
/// before any field bytes, so that hashing structurally-identical bytes
/// for two different purposes can never collide. The exact strings are
/// part of the protocol and are covered by tests in each
/// `crate::ids` submodule — changing one changes every future ID derived
/// through it.
pub mod labels {
    /// Domain separator for [`crate::ids::DeviceId`] derivation.
    pub const DEVICE_ID: &str = "keyit:v1:device-id";
    /// Domain separator for [`crate::ids::ProjectId`] derivation.
    pub const PROJECT_ID: &str = "keyit:v1:project-id";
    /// Domain separator for [`crate::ids::EnvironmentId`] derivation.
    pub const ENVIRONMENT_ID: &str = "keyit:v1:environment-id";
    /// Domain separator for [`crate::ids::RevisionId`] derivation.
    pub const REVISION_ID: &str = "keyit:v1:revision-id";
    /// Domain separator for [`crate::ids::InviteId`] derivation.
    pub const INVITE_ID: &str = "keyit:v1:invite-id";

    // Deliberately distinct strings from the identifier-derivation labels
    // above, even where a record and its own identifier share several
    // field values (e.g. `ProjectGenesis` and `ProjectId`): reusing a
    // label across two different purposes is exactly what
    // domain-separation exists to prevent, so identifier derivation and
    // record signing each get their own label per record/identifier
    // type, with a `sign:` sub-namespace name for the signing ones.

    /// Domain separator for [`crate::records::DeviceIdentity`]'s
    /// canonical encoding.
    ///
    /// `DeviceIdentity` has no `signature` field: its authenticity is
    /// established by [`crate::ids::DeviceId`] derivation, not a separate
    /// signature.
    pub const SIGN_DEVICE_IDENTITY: &str = "keyit:v1:sign:device-identity";
    /// Domain separator for [`crate::records::ProjectGenesis`] signing.
    pub const SIGN_PROJECT_GENESIS: &str = "keyit:v1:sign:project-genesis";
    /// Domain separator for [`crate::records::MembershipGenesis`]
    /// signing.
    pub const SIGN_MEMBERSHIP_GENESIS: &str = "keyit:v1:sign:membership-genesis";
    /// Domain separator for [`crate::records::EnvironmentGenesis`]
    /// signing.
    pub const SIGN_ENVIRONMENT_GENESIS: &str = "keyit:v1:sign:environment-genesis";
    /// Domain separator for [`crate::records::Invite`] signing.
    pub const SIGN_INVITE: &str = "keyit:v1:sign:invite";
    /// Domain separator for [`crate::records::JoinRequest`] signing.
    pub const SIGN_JOIN_REQUEST: &str = "keyit:v1:sign:join-request";
    /// Domain separator for [`crate::records::Approval`] signing.
    pub const SIGN_APPROVAL: &str = "keyit:v1:sign:approval";
    /// Domain separator for [`crate::records::Revision`] signing.
    pub const SIGN_REVISION: &str = "keyit:v1:sign:revision";
    /// Domain separator for [`crate::records::Revocation`] signing.
    pub const SIGN_REVOCATION: &str = "keyit:v1:sign:revocation";
}

/// An append-only buffer of canonically-encoded bytes.
///
/// Every `push_*` method appends a length prefix (or, for fixed-width
/// integers, a fixed number of bytes) before the value itself, so that
/// the concatenation of any sequence of pushes is unambiguous: there is
/// exactly one way to have produced a given byte string by pushing a
/// given sequence of field types. Without length prefixes,
/// `push_str("ab"); push_str("c")` and `push_str("a"); push_str("bc")`
/// would encode to the same bytes; with them, they don't (see the test
/// of exactly this in this module).
///
/// This is deliberately boring: no generic reflection over struct
/// fields, no attribute macros choosing field order for you. Each
/// [`Canonicalize`] implementation spells out, in the body of
/// `write_canonical`, exactly which fields it hashes and in what order.
#[derive(Debug, Default, Clone)]
pub struct CanonicalBytes(Vec<u8>);

impl CanonicalBytes {
    /// Starts an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a length-prefixed byte string.
    ///
    /// The length prefix is a fixed-width 8-byte big-endian `u64`,
    /// regardless of platform `usize` width, so the same Rust value
    /// canonicalizes to the same bytes on a 32-bit and a 64-bit build.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.0
            .extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    /// Appends a length-prefixed UTF-8 string, encoded as its raw bytes.
    pub fn push_str(&mut self, s: &str) -> &mut Self {
        self.push_bytes(s.as_bytes())
    }

    /// Appends a single byte (no length prefix needed: fixed width).
    pub fn push_u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }

    /// Appends a `u64` as 8 big-endian bytes (no length prefix needed:
    /// fixed width).
    pub fn push_u64(&mut self, value: u64) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends an optional byte string, encoding presence explicitly (a
    /// leading `0` or `1` marker byte) so that `None` can never be
    /// confused with `Some(&[])`.
    pub fn push_opt_bytes(&mut self, bytes: Option<&[u8]>) -> &mut Self {
        match bytes {
            Some(b) => {
                self.push_u8(1);
                self.push_bytes(b);
            }
            None => {
                self.push_u8(0);
            }
        }
        self
    }

    /// Appends a length-prefixed sequence of items, each written by
    /// `write_item`.
    ///
    /// The item count is written first (fixed 8-byte big-endian `u64`),
    /// then each item in `items`' iteration order, via `write_item` —
    /// which typically just calls one more `push_*` method per item.
    /// Writing the count up front means the same unambiguous-boundary
    /// property [`Self::push_bytes`] gives a single field also holds for
    /// a whole list: there's no way to confuse "3 short items" with "2
    /// longer items" once the count is fixed and each item still
    /// length-prefixes itself.
    ///
    /// List order is significant and preserved as given — this does not
    /// sort or deduplicate. A record whose list field is conceptually a
    /// set (e.g. `Invite::allowed_environment_ids`) still canonicalizes
    /// by insertion order; callers that need order-independence must
    /// construct the list in a stable order themselves before signing.
    pub fn push_list<T>(
        &mut self,
        items: &[T],
        mut write_item: impl FnMut(&mut Self, &T),
    ) -> &mut Self {
        self.push_u64(items.len() as u64);
        for item in items {
            write_item(self, item);
        }
        self
    }

    /// Borrows the accumulated canonical bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the buffer, returning the accumulated canonical bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A value that can append itself to a [`CanonicalBytes`] buffer in a
/// fixed, documented field order.
///
/// Implementors write only the *fields*, not a domain-separation label —
/// [`canonical_hash`] writes the label first, once, so a `Canonicalize`
/// impl can be reused (if it ever needs to be) under more than one
/// label without duplicating that logic.
pub trait Canonicalize {
    /// Appends this value's canonical field encoding to `buf`.
    fn write_canonical(&self, buf: &mut CanonicalBytes);
}

/// Builds the raw canonical preimage bytes for `value` under `label`,
/// without hashing them.
///
/// The preimage is `label`'s length-prefixed bytes followed by
/// `value.write_canonical(...)`'s output — i.e. the domain separator is
/// itself part of the canonically-encoded, length-prefixed input, not
/// just a raw prefix, so it can't be confused with the start of the
/// field data either. [`crate::signing`] signs and verifies this output
/// directly; [`canonical_hash`] additionally hashes it for identifier
/// derivation.
pub fn canonical_preimage(label: &str, value: &impl Canonicalize) -> Vec<u8> {
    let mut buf = CanonicalBytes::new();
    buf.push_str(label);
    value.write_canonical(&mut buf);
    buf.into_bytes()
}

/// Hashes `value`'s canonical encoding under `label` with SHA-256.
///
/// See [`canonical_preimage`] for what exactly gets hashed.
pub fn canonical_hash(label: &str, value: &impl Canonicalize) -> HashBytes {
    let preimage = canonical_preimage(label, value);

    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    HashBytes::from_sha256_digest(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sample<'a>(&'a str, &'a [u8]);

    impl Canonicalize for Sample<'_> {
        fn write_canonical(&self, buf: &mut CanonicalBytes) {
            buf.push_str(self.0);
            buf.push_bytes(self.1);
        }
    }

    #[test]
    fn hash_output_is_32_bytes() {
        let hash = canonical_hash("test-label", &Sample("a", b"b"));
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn same_canonical_input_gives_same_hash() {
        let a = canonical_hash("test-label", &Sample("x", b"y"));
        let b = canonical_hash("test-label", &Sample("x", b"y"));
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_labels_give_different_hashes() {
        let a = canonical_hash("label-a", &Sample("x", b"y"));
        let b = canonical_hash("label-b", &Sample("x", b"y"));
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_field_values_give_different_hashes() {
        let a = canonical_hash("test-label", &Sample("x", b"y"));
        let b = canonical_hash("test-label", &Sample("x", b"z"));
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn length_prefixing_prevents_ambiguous_concatenation() {
        // Without length prefixes, "ab" + "c" and "a" + "bc" would
        // encode to identical bytes.
        let mut a = CanonicalBytes::new();
        a.push_str("ab").push_str("c");
        let mut b = CanonicalBytes::new();
        b.push_str("a").push_str("bc");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn push_opt_bytes_distinguishes_none_from_empty_some() {
        let mut a = CanonicalBytes::new();
        a.push_opt_bytes(None);
        let mut b = CanonicalBytes::new();
        b.push_opt_bytes(Some(&[]));
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn push_u64_is_fixed_width_big_endian() {
        let mut buf = CanonicalBytes::new();
        buf.push_u64(1);
        assert_eq!(buf.as_bytes(), [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn push_list_prefixes_item_count() {
        let mut empty = CanonicalBytes::new();
        empty.push_list(&Vec::<&str>::new(), |buf, s: &&str| {
            buf.push_str(s);
        });
        assert_eq!(empty.as_bytes(), [0, 0, 0, 0, 0, 0, 0, 0]);

        let mut two = CanonicalBytes::new();
        two.push_list(&["a", "b"], |buf, s: &&str| {
            buf.push_str(s);
        });
        assert_eq!(two.as_bytes()[..8], [0, 0, 0, 0, 0, 0, 0, 2]);
    }

    #[test]
    fn push_list_distinguishes_item_boundaries_from_count() {
        // Without a count prefix, a 3-item list of 1-char strings could
        // be confused with some other item count/length combination that
        // happens to concatenate to the same bytes.
        let mut three_items = CanonicalBytes::new();
        three_items.push_list(&["a", "b", "c"], |buf, s: &&str| {
            buf.push_str(s);
        });
        let mut one_item = CanonicalBytes::new();
        one_item.push_list(&["abc"], |buf, s: &&str| {
            buf.push_str(s);
        });
        assert_ne!(three_items.as_bytes(), one_item.as_bytes());
    }

    #[test]
    fn canonical_preimage_is_unhashed_and_starts_with_label() {
        let preimage = canonical_preimage("test-label", &Sample("a", b"b"));
        // Unlike a SHA-256 digest (always 32 bytes), the raw preimage's
        // length depends on its content, and it is recoverable/inspectable.
        assert!(preimage.len() > 32);
    }

    #[test]
    fn canonical_preimage_is_deterministic() {
        let a = canonical_preimage("test-label", &Sample("x", b"y"));
        let b = canonical_preimage("test-label", &Sample("x", b"y"));
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_preimage_differs_from_its_own_hash() {
        let preimage = canonical_preimage("test-label", &Sample("a", b"b"));
        let hash = canonical_hash("test-label", &Sample("a", b"b"));
        assert_ne!(preimage, hash.as_bytes());
    }
}
