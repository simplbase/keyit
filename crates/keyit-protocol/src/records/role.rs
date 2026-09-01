/// A member's role within a project.
///
/// `docs/protocol/keyit-protocol-v1.md` explicitly names `owner` (the
/// project creator, via `MembershipGenesis`) and refers to "an owner or
/// admin device" performing approvals and revocations; `member` is the
/// implied baseline role for anyone approved without elevated
/// privileges. The exact permission differences between `Admin` and
/// `Member` are not yet specified, so this enum only records which role
/// a member holds, not what each role can do.
///
/// `#[non_exhaustive]` because the protocol document does not claim this
/// is the final role set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Role {
    /// The project creator, or a member granted equivalent standing.
    Owner,
    /// A member trusted to approve joins and revoke access, but not
    /// necessarily with full owner standing.
    Admin,
    /// A member with project/environment access but no approval or
    /// revocation authority.
    Member,
}

impl Role {
    /// Canonical string form, used in
    /// [`crate::canonical::Canonicalize`] implementations
    /// ([`crate::records::MembershipGenesis`],
    /// [`crate::records::Approval`]) so a role's signed encoding does
    /// not depend on the enum's discriminant values or variant order.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_distinct() {
        assert_ne!(Role::Owner, Role::Admin);
        assert_ne!(Role::Admin, Role::Member);
        assert_ne!(Role::Owner, Role::Member);
    }

    #[test]
    fn as_str_matches_protocol_document_notation() {
        assert_eq!(Role::Owner.as_str(), "owner");
        assert_eq!(Role::Admin.as_str(), "admin");
        assert_eq!(Role::Member.as_str(), "member");
    }

    #[test]
    fn as_str_values_are_distinct() {
        assert_ne!(Role::Owner.as_str(), Role::Admin.as_str());
        assert_ne!(Role::Admin.as_str(), Role::Member.as_str());
        assert_ne!(Role::Owner.as_str(), Role::Member.as_str());
    }
}
