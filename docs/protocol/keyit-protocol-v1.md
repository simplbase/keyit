# Keyit Protocol v1

## Status

Frozen conceptual protocol spine.

This document records Keyit's v1 protocol primitives and security model.
For the implementation structure, see [`../architecture.md`](../architecture.md).

## Product Boundary

Keyit is an open-source, local-first protocol and CLI for securely
synchronizing private project state across authorized developers and
machines.

V1 focuses on dotenv-style project environment files.

Keyit must allow developers to share private project environment state
without:

- committing secrets to Git
- emailing dotenv files
- using chat tools as secret stores
- requiring static IP addresses
- exposing ports
- requiring a VPN
- depending on Google or GitHub OAuth
- requiring email or phone verification
- trusting the Keyit Relay with plaintext secrets

The core v1 promise is:

```text
Clone the project. Join Keyit. Pull the environment. Start developing.
```

## Architecture

Keyit has three major components:

```text
             Keyit Protocol/Core
                ^           ^
                |           |
          Keyit CLI     Keyit Relay
```

The protocol/core defines identities, projects, environments,
membership, invitations, encryption boundaries, revisions,
synchronization, conflict handling, and revocation.

The CLI is the developer-facing client.

The relay is untrusted infrastructure that stores and distributes
encrypted state and public/verifiable protocol metadata.

## Identifier Namespaces

Keyit uses namespaced identifiers:

```text
kvd_    Device
kvp_    Project
kve_    Environment
kvr_    Revision
kvi_    Invitation
```

Where appropriate, identifiers are derived from canonical public protocol
material rather than human names, folder names, Git remotes, emails, or
random labels.

Identifiers use canonical public protocol material rather than mutable
human labels.

## 1. Identity

Keyit has no global user accounts. The primary protocol actor is a
device identity.

Each device independently generates its identity. A developer's MacBook
and Linux workstation are separate identities even if they belong to the
same person.

Each device has two distinct key pairs:

```text
Device Identity
|-- Signing Key Pair
|   `-- Ed25519
`-- Key Agreement Key Pair
    `-- X25519
```

Ed25519 is used to prove that a device authorized or signed a protocol
action.

X25519 is used for key agreement and secure distribution of environment
key material to authorized devices.

Conceptually:

```text
DeviceIdentity {
    protocol_version
    device_id
    signing_public_key
    encryption_public_key
    created_at
}
```

Private keys must never be stored in a project repository or relay
object.
Where available, private key material should use native secure storage:

```text
macOS      Keychain
Windows    secure OS credential/key storage
Linux      Secret Service where available
```

Device labels are untrusted metadata. Anyone can label a device
`Kiruthik MacBook`; the cryptographic public identity is authoritative.

Frozen rules:

1. Keyit has no global user accounts.
2. The primary protocol actor is a device identity.
3. Each device independently generates its identity.
4. Ed25519 signing and X25519 key agreement use separate key pairs.
5. Private keys never leave the originating device under normal Keyit
   operation.
6. Device IDs are derived from cryptographic public identity, not
   usernames or random human identity.
7. Device labels are untrusted metadata.
8. A device identity alone grants no project access.
9. Authorization is established through project membership.
10. Relay authentication is cryptographic rather than account/password
    based.
11. V1 does not support copying or exporting device identities between
    machines.
12. A new machine means a new Keyit device identity.
13. Revocation prevents future access but cannot revoke plaintext
    previously learned by a device.
14. No email, phone, OAuth, GitHub account, IP address, or hardware
    identifier forms part of Keyit identity.

## 2. Project Genesis

`keyit init` creates a Keyit Project, not just a local config folder.

A Keyit Project is the cryptographic boundary for shared private project
state.

```text
Git Repository
`-- keyit.toml
    `-- project locator and genesis hash

Developer Device
`-- private Keyit identity, keys, and local cache
```

A project is not identified by Git remote URL, folder name, GitHub repo
name, organization name, domain name, or human account.

Every project gets a stable project identifier:

```text
kvp_...
```

The project ID should be derived from a canonical project genesis
document that includes a high-entropy genesis nonce.

Conceptually:

```text
ProjectGenesis {
    protocol_version
    project_id
    genesis_nonce
    created_at
    creator_device_id
    creator_device_public_identity
    project_label
    default_relay_url
    canonicalization_version
    signature
}
```

The creator signs the genesis document with its Ed25519 signing key.

The device that runs `keyit init` becomes the first project owner:

```text
MembershipGenesis {
    project_id
    member_device_id
    role = owner
    approved_by = genesis
    created_at
    signature
}
```

The project repository commits only `keyit.toml`. It is a small locator
and trust anchor containing the project ID, project-genesis hash, relay
URL, and environment labels. Mutable `.keyit/` runtime state is a local
cache under the Keyit data directory, not a repository artifact.

Allowed in `keyit.toml`:

```text
project_id
project label
relay URL
environment IDs
environment labels
local path hints
project genesis hash
```

Forbidden in `keyit.toml` and project repositories:

```text
plaintext dotenv values
environment DEKs
device private keys
unwrapped keys
local runtime caches
local-only credentials
OS keychain material
```

Environment creation is separate from project creation. `keyit init`
must not silently publish, encrypt, or upload dotenv files.

Frozen rules:

1. `keyit init` creates a cryptographic Keyit Project.
2. A project is identified by `kvp_...`, not by folder name, Git URL,
   GitHub repo, or account.
3. Project ID is derived from canonical genesis material.
4. Genesis includes a high-entropy nonce so project IDs are globally
   unique.
5. The creator device signs the genesis document.
6. The creator device becomes the first project owner.
7. Project ownership belongs to device identities, not human accounts.
8. `keyit.toml` contains locator metadata only; mutable protocol state is
   stored locally and on the relay.
9. Private keys, plaintext secrets, DEKs, and invite bearer secrets must
   never be committed.
10. Environment creation is separate from project creation.
11. `keyit init` must not silently publish or encrypt dotenv files.
12. Relay configuration is metadata, not a trust anchor.
13. The hosted Keyit relay is optional infrastructure, not part of the
    protocol identity.
14. Project genesis is the root of all future membership, environment,
    and revision verification.

## 3. Environment Model

A Keyit Project can contain multiple environments.

An environment is the boundary around one shared private-state document,
usually a dotenv file.

```text
Project kvp_X
|-- Environment kve_A  development  dotenv/v1
|-- Environment kve_B  testing      dotenv/v1
`-- Environment kve_C  staging      dotenv/v1
```

Each environment is independent. Development and staging do not share the
same encryption key, revision chain, or access policy by default.

Each environment gets a stable identifier:

```text
kve_...
```

The environment ID should be derived from canonical environment creation
material. The human label, such as `development`, is metadata.

An environment is created explicitly:

```text
keyit env add development .env.local
```

Conceptually:

```text
EnvironmentGenesis {
    protocol_version
    project_id
    environment_id
    environment_label
    document_type
    local_path_hint
    created_at
    created_by_device_id
    parent_project_genesis_hash
    signature
}
```

V1 supports one official document type:

```text
dotenv/v1
```

The local file path is a machine-local materialization target, not
protocol identity. Two developers may map the same environment to
different local files.

Each environment has its own:

```text
environment_id
document type
revision chain
data encryption key
member access set
wrapped keys
conflict scope
rollback scope
```

Project membership and environment access are related but not identical.
A device may be a project member but only have access to selected
environments.

Environment creation is separate from first secret publication.

Frozen rules:

1. A Keyit Project may contain multiple environments.
2. Each environment has a stable `kve_...` identifier.
3. Environment labels like `development` are metadata, not identity.
4. V1 officially supports `dotenv/v1`.
5. Local file paths are machine-local mappings, not protocol identity.
6. Each environment has its own encryption boundary.
7. Each environment has its own revision chain.
8. Each environment has its own access set.
9. Project membership does not automatically imply access to every
   environment.
10. Environment creation is explicit.
11. Environment creation is separate from first secret publication.
12. Environment metadata may be committed only if it contains no
    plaintext secrets or unwrapped keys.
13. Environment genesis is signed by the creating device.
14. Environment rollback, conflict detection, and revision history are
    scoped per environment.

## 4. Key Model

Each environment has its own random data encryption key.

```text
Project kvp_X
|-- development -> DEK-A
|-- testing     -> DEK-B
`-- staging     -> DEK-C
```

The DEK encrypts the dotenv payload. The DEK itself is never stored in
plaintext on the relay, in `keyit.toml`, or in the local runtime cache.

For every authorized device, Keyit stores a wrapped copy:

```text
development DEK
|-- wrapped for kvd_A
|-- wrapped for kvd_B
`-- wrapped for kvd_C
```

Frozen rules:

1. Environment DEKs are random symmetric keys.
2. Each environment has a separate DEK.
3. Plaintext DEKs never leave authorized devices.
4. The relay may store wrapped DEKs only.
5. Adding a member means wrapping the relevant environment DEK for that
   device.
6. Revoking a member requires future DEK rotation for affected
   environments.
7. Project keys and device keys must not be reused as environment DEKs.

## 5. Invite

An invite is not access. It is only permission to request membership.

```text
keyit invite --env development --expires 1h --uses 1
```

Conceptually:

```text
Invite {
    invite_id = kvi_...
    project_id
    allowed_environment_ids
    created_by_device_id
    expires_at
    max_uses
    status
    signature
}
```

The invite link or code is a bearer secret and must not be committed.

```text
https://keyit.sh/join/kvi_...
```

Frozen rules:

1. Invite possession does not grant secrets.
2. Invites only allow creation of join requests.
3. Invites can be environment-scoped.
4. Invites must support expiry.
5. Invites must support maximum uses.
6. Invite metadata is signed by the creator.
7. Invite bearer secrets must not be stored in Git.
8. Keyit does not care how the invite is transported.

## 6. Join

A joining device presents its public identity and proves possession of
its signing key.

```text
keyit join kvi_...
```

Conceptually:

```text
JoinRequest {
    project_id
    invite_id
    joining_device_id
    joining_device_public_identity
    requested_environment_ids
    device_label
    created_at
    proof_signature
}
```

The relay may hold this as a pending request.

Frozen rules:

1. Joining does not grant access.
2. The joining device must prove control of its private signing key.
3. Device label remains untrusted metadata.
4. Join requests are pending until approved.
5. A join request may ask for one or more environments.
6. The relay may store pending join requests, but cannot approve them by
   itself.

## 7. Approval

Approval is the cryptographic act that grants access.

An owner or admin reviews the pending device:

```text
keyit members
keyit approve kvd_...
```

Approval creates signed membership/access records and wraps environment
DEKs for the approved device.

Conceptually:

```text
Approval {
    project_id
    approved_device_id
    approved_environment_ids
    role
    approved_by_device_id
    created_at
    signature
}
```

Frozen rules:

1. Approval must be explicit.
2. Approval is performed by an already-authorized owner/admin device.
3. Approval may be scoped to selected environments.
4. Approval creates signed membership state.
5. Approval creates wrapped DEKs for the approved device.
6. The relay cannot invent approval.
7. A device is not authorized unless a valid signed approval chain
   exists.

## 8. Push

Push publishes a new encrypted environment revision.

```text
keyit push development
```

Push performs:

```text
read local dotenv
validate dotenv
compare with base revision
encrypt validated source payload with environment DEK
create revision
sign revision
upload ciphertext and metadata
```

Push must be explicit. Keyit must not silently publish changed dotenv
files.

Frozen rules:

1. Push is manual and explicit.
2. Push is environment-scoped.
3. Plaintext is encrypted before upload.
4. The relay receives ciphertext only.
5. Every push creates a signed revision.
6. Push must reference the previous known revision.
7. Push must fail if the local base revision is stale and conflict rules
   are triggered.
8. Secret values must not appear in default push output.
9. The author is the signing device, not a username.
10. A pushed revision is append-only; it does not rewrite history.

## 9. Revision Chain

Every environment has its own append-only signed revision chain.

```text
Environment kve_A
|-- rev 1
|-- rev 2
`-- rev 3
```

Conceptually:

```text
Revision {
    revision_id = kvr_...
    project_id
    environment_id
    parent_revision_id
    parent_revision_hash
    payload_hash
    encrypted_payload_ref
    author_device_id
    created_at
    change_summary
    signature
}
```

The signature covers the revision metadata and payload hash.

Frozen rules:

1. Revision chains are per environment.
2. Each revision references its parent.
3. Each revision is signed by the author device.
4. Revisions are append-only.
5. Rollback creates a new revision; it does not delete history.
6. The relay may store revisions but cannot forge valid revisions.
7. Revision IDs use the `kvr_...` namespace.
8. Revision verification must check signature, hashes, project ID,
   environment ID, and ancestry.

## 10. Pull

Pull retrieves and materializes encrypted state locally.

```text
keyit pull development
```

Pull performs:

```text
download latest revision metadata
verify revision chain
download ciphertext
verify payload hash
unwrap environment DEK locally
decrypt payload locally
write local dotenv file
record materialized revision
```

Frozen rules:

1. Pull is environment-scoped.
2. Pull must verify before decrypting.
3. The relay is not trusted to choose valid state blindly.
4. Pull must verify signatures and ancestry.
5. DEKs are unwrapped only on authorized devices.
6. Plaintext is materialized only on the local machine.
7. Pull should not overwrite uncommitted local secret changes without
   warning.
8. Secret values must not appear in default pull output.

## 11. Conflict Handling

Conflicts are detected when a device tries to push from a stale base
revision.

```text
Alice pulls v10
Bob pulls v10

Alice pushes v11
Bob edits the same key
Bob tries to push from v10
```

Bob's push must not silently overwrite Alice's change.

Keyit can compare key-level metadata without exposing values.

Frozen rules:

1. Conflict detection is per environment.
2. A push must declare its base revision.
3. If remote head has advanced, Keyit must check for conflicts.
4. Same-key concurrent changes are conflicts.
5. Non-overlapping key changes may be mergeable later, but V1 can require
   explicit user action.
6. Keyit must never auto-resolve by exposing secret values in output.
7. Conflict resolution creates a new signed revision.
8. Failed conflict pushes must not create accepted revisions.

## 12. Revocation

Revocation removes a device's future access.

```text
keyit revoke kvd_...
```

Conceptually:

```text
Revocation {
    project_id
    revoked_device_id
    affected_environment_ids
    revoked_by_device_id
    created_at
    reason_optional
    signature
}
```

After revocation:

```text
old DEK -> deprecated
new DEK -> wrapped only for remaining authorized devices
```

Frozen rules:

1. Revocation is explicit.
2. Revocation is signed by an authorized owner/admin device.
3. Revocation is scoped to project/environment access.
4. Revoked devices must not receive future wrapped DEKs.
5. Affected environment DEKs must rotate after revocation.
6. Revocation cannot erase secrets already decrypted by the revoked
   device.
7. Revocation creates append-only membership history.
8. The relay cannot revoke members by itself.

## 13. Relay Contract

The relay provides availability and synchronization, not trust.

It may store:

```text
project IDs
environment IDs
public device identities
join requests
membership records
revision metadata
encrypted payloads
wrapped DEKs
timestamps
```

It must never store:

```text
plaintext dotenv values
unwrapped DEKs
device private keys
plaintext invite bearer secrets
```

Relay behavior:

```text
client uploads signed/encrypted state
relay stores and distributes it
clients verify everything locally
```

Frozen rules:

1. The relay is untrusted.
2. The relay must not be required to see plaintext.
3. Clients verify signatures, hashes, ancestry, and membership locally.
4. The relay may reject malformed or unauthorized-looking requests, but
   client verification remains authoritative.
5. Hosted relay and self-hosted relay must obey the same protocol.
6. Relay URL is configuration, not protocol identity.
7. Relay storage is replaceable infrastructure.
8. Relay compromise must not reveal plaintext secrets if client
   cryptography is correct.
9. Relay compromise may affect availability and metadata privacy.
10. The relay cannot grant access without valid signed approval and
    wrapped keys.

## Frozen Primitive Set

Keyit v1 has thirteen frozen protocol primitives:

```text
1. Identity
2. Project Genesis
3. Environment Model
4. Key Model
5. Invite
6. Join
7. Approval
8. Push
9. Revision Chain
10. Pull
11. Conflict Handling
12. Revocation
13. Relay Contract
```

The stable conceptual spine is:

```text
Device Identity
   |
   v
Project Genesis
   |
   v
Environment Genesis
   |
   v
Membership / Access
   |
   v
Encrypted Revisions
   |
   v
Verification / Pull
   |
   v
Conflict / Revocation
   |
   v
Untrusted Relay
```

## Known Limits

The following areas are intentionally conservative in the current v1
implementation:

- public canonical serialization commitments beyond the current Rust
  implementation
- database/object-store backed relay storage
- revision merge rules beyond same-key conflict detection
- OS-specific private key storage outside macOS and file-backed
  development use
- multi-instance hosted relay operation
