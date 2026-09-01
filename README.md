# Keyit

Portable private state for software projects.

Keyit is a CLI and relay protocol for synchronizing project environment
files across approved developer machines. It is designed for dotenv-style
files such as `.env.local`: one device pushes an encrypted revision,
another approved device pulls it, and the relay never sees plaintext
secrets.

```text
Developer A
    |
    | keyit push
    v
Untrusted Keyit Relay
    |
    | encrypted state
    v
Developer B
    |
    | keyit pull
    v
.env.local
```

Keyit does not require user accounts, OAuth, email verification, VPNs,
static IPs, or Git hosting access. Identity is device-scoped and
cryptographic.

## Relay

Two ways to run it, same untrusted design either way:

- **Hosted**, at `https://relay.keyit.sh` — zero-ops. No signup;
  `keyit init` works immediately after install.
- **Self-hosted** — run the same `keyit-relay` binary or container
  under your own infrastructure when you need control over where relay
  data lives, or compliance requirements the hosted relay doesn't meet.
  See [Relay container deployment](docs/relay-container-deployment.md)
  and [Relay production operation](docs/relay-production.md).

The relay never receives plaintext dotenv values or unwrapped
encryption keys, hosted or self-hosted.

## Status

Keyit is early software and should be treated as private beta. The core
project flow is implemented and usable for controlled internal projects:

- project initialization
- environment registration
- encrypted push and pull
- hosted relay access at `https://relay.keyit.sh`
- invite, join, approve, and revoke flows
- local conflict and overwrite protection
- release binaries and relay container images

Keyit has not yet undergone an external security audit. Do not use it as
the only control protecting high-value production secrets.

## Install

With Homebrew:

```sh
brew tap simplbase/tap
brew install keyit
```

On Ubuntu and other Linux distributions:

```sh
curl -fsSL https://raw.githubusercontent.com/simplbase/keyit/main/packaging/install-release.sh | sh
```

This installs:

```text
$HOME/.local/bin/keyit
$HOME/.local/bin/keyit-relay
```

See [docs/installation.md](docs/installation.md) for alternate install
locations, version pinning, Windows binaries, and shell completions.

## First Project

From a project repository:

```sh
keyit relay check
keyit init --project-label my-project
keyit env add development .env.local
keyit push development --summary "Initial development env"
```

Commit only the small project locator. Keyit does not create a
`.gitignore` for you, so add the plaintext-secret exclusions yourself
before committing:

```sh
printf '.env\n.env.*\n!.env.example\n' >> .gitignore
git add keyit.toml .gitignore
git commit -m "Add Keyit project locator"
```

Do not commit `.env`, `.env.local`, `.keyit/`, or other plaintext secret
files. Keyit runtime state is stored under your local Keyit data
directory, not inside the project repository.

## Add Another Device

Owner device:

```sh
keyit invite create --env development --expires-at 4102444800 --max-uses 1
```

Joining device:

```sh
keyit join /path/to/invite.bundle --env development
```

Owner device:

```sh
keyit approve <device-id> --role member
keyit push development --summary "Grant development env access"
```

Joining device:

```sh
keyit pull development
```

## Commands

The `keyit` CLI includes:

```text
init
env add
env list
push
pull
status
diff
whoami
revision list
invite create
join
approve
revoke
relay check
version
completions
```

The `keyit-relay` binary serves the HTTP relay and exposes maintenance
commands for storage inspection and cleanup.

## Documentation

- [Architecture](docs/architecture.md)
- [Installation](docs/installation.md)
- [Try Keyit locally](docs/try-local.md)
- [Release flow](docs/release.md)
- [Relay container deployment](docs/relay-container-deployment.md)
- [Relay production operation](docs/relay-production.md)
- [Protocol reference](docs/protocol/keyit-protocol-v1.md)
- [Security policy](SECURITY.md)

## Workspace

Keyit is a Rust workspace with three crates:

- `keyit-protocol` - core domain model, cryptographic records, signing,
  encryption, and canonical encoding
- `keyit-cli` - developer-facing command-line workflows
- `keyit-relay` - untrusted relay service

The protocol crate is the dependency root. CLI and relay code depend on
it, and it does not depend on either of them.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
