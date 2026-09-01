# Keyit Architecture

Keyit is a local-first secret synchronization system for project
environment files. The relay is intentionally untrusted: it stores and
serves encrypted protocol records, but it never receives plaintext
dotenv values or private device keys.

## Components

The repository is a single Rust workspace with three crates:

| Crate | Purpose |
| --- | --- |
| `keyit-protocol` | Core protocol types, identifiers, canonical encoding, signing, encryption, and record verification. |
| `keyit-cli` | Developer-facing command-line workflows such as init, push, pull, invite, join, approve, and revoke. |
| `keyit-relay` | HTTP relay service for storing and distributing encrypted revisions and access records. |

Dependency direction is one-way:

```text
keyit-protocol
   ^      ^
   |      |
keyit-cli keyit-relay
```

The protocol crate must not depend on CLI or relay code. This keeps the
domain model testable and prevents infrastructure concerns from leaking
into cryptographic record definitions.

## Identity Model

Keyit identity is device-scoped. A developer's laptop and workstation
are separate cryptographic actors unless the project owner explicitly
approves both.

Each device has two key pairs:

- Ed25519 for signing protocol actions
- X25519 for environment key agreement and wrapping

Private keys are stored outside project repositories. Project
repositories commit only `keyit.toml`, a small locator containing the
project ID, pinned project-genesis hash, relay URL, and environment
labels. Mutable Keyit runtime state lives under the local Keyit data
directory.

## Project And Environment Model

A Keyit project can contain multiple environments, such as
`development`, `staging`, or `production`. Each environment has:

- a signed environment genesis record
- its own encrypted revision chain
- its own access scope
- its own dotenv file mapping, such as `.env.local`

Environment plaintext remains local to approved devices. A push validates
the mapped dotenv file, encrypts the validated source text, wraps the
data-encryption key for active authorized devices, signs the revision,
and publishes the encrypted result. Comments, blank lines, and grouping
inside the dotenv file are preserved when another approved device pulls
the revision.

## Relay Model

The relay is a storage and synchronization service, not a trust anchor.
It receives signed requests and validates public metadata authorization,
but it cannot decrypt environment payloads.

The hosted relay is:

```text
https://relay.keyit.sh
```

Most projects use the hosted relay: no signup and nothing to run —
`keyit init` works immediately after install. Self-hosting the same
`keyit-relay` binary or container is for teams that need direct control
over where relay data lives — on-prem placement, network isolation, or
compliance requirements the hosted relay doesn't satisfy. See
[Relay container deployment](relay-container-deployment.md) and
[Relay production operation](relay-production.md). Either way, the
relay is untrusted: it never receives plaintext dotenv values or
unwrapped encryption keys.

The relay exposes:

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- signed project/environment revision routes
- signed project, environment, invite, join, approval, and revocation
  record routes

The production container runs with a private mounted data directory and
is normally placed behind a TLS reverse proxy such as Caddy.

## Access Flow

Owner device:

```text
keyit invite create
```

Joining device:

```text
keyit join <invite-bundle>
```

Owner device:

```text
keyit approve <device-id>
keyit push <environment>
```

Approved device:

```text
keyit pull <environment>
```

Invite bundles contain public signed project bootstrap metadata, the
signed invite, and the public access-chain records needed to verify the
inviter. They do not grant access by themselves; an owner or admin
approval is still required before the joining device can decrypt
environment revisions.

## Revocation And Rotation

Revocation prevents future access by removing a device from the active
authorization set. It cannot erase plaintext or wrapped keys that the
revoked device already received.

After revocation, affected environments are marked for rotation. The
next owner/admin push publishes a fresh encrypted revision with key
material wrapped only for active devices.

## Public Safety Rules

- Do not commit plaintext dotenv files.
- Commit `keyit.toml`; do not commit local `.keyit/` runtime caches.
- Do not store private device keys inside a project repository.
- Treat invite bundles as private onboarding material.
- Treat relay storage as public to the relay operator.
- Keep `.env.example` for documentation and `.env.local` for secrets.
