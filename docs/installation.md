# Keyit Installation

## Homebrew

On macOS or Linux with Homebrew:

```bash
brew tap simplbase/tap
brew install keyit
```

This installs:

```text
keyit
keyit-relay
```

## Ubuntu And Linux

For a user-local install:

```bash
curl -fsSL https://raw.githubusercontent.com/simplbase/keyit/main/packaging/install-release.sh | sh
```

This installs:

```text
$HOME/.local/bin/keyit
$HOME/.local/bin/keyit-relay
```

Make sure `$HOME/.local/bin` is on `PATH`.

For a system install on Ubuntu:

```bash
curl -fsSL https://raw.githubusercontent.com/simplbase/keyit/main/packaging/install-release.sh | sudo env PREFIX=/usr/local sh
```

This installs:

```text
/usr/local/bin/keyit
/usr/local/bin/keyit-relay
```

Install somewhere else with:

```bash
curl -fsSL https://raw.githubusercontent.com/simplbase/keyit/main/packaging/install-release.sh | PREFIX=/usr/local sh
```

Install a specific version with:

```bash
curl -fsSL https://raw.githubusercontent.com/simplbase/keyit/main/packaging/install-release.sh | KEYIT_VERSION=v1.0.0 sh
```

The installer downloads the matching GitHub Release archive, verifies it
against `SHA256SUMS`, and installs the `keyit` and `keyit-relay`
binaries.

## Windows

Download the Windows ZIP archive from the GitHub Release page, verify it
against `SHA256SUMS`, and place `keyit.exe` somewhere on `PATH`.

The release archive also includes `keyit-relay.exe` for relay operators.

## Install From Source

Use this when you are working from a checkout or need a build that has
not been released yet:

```bash
PREFIX="$HOME/.local" ./packaging/install.sh
```

This builds the workspace binaries with the locked dependency graph and
installs:

```text
$PREFIX/bin/keyit
$PREFIX/bin/keyit-relay
```

## First Project

```bash
keyit relay check
keyit init
keyit env add development .env.local
keyit push development
keyit pull development
```

Commit `keyit.toml` to the project repository. Do not commit `.env`,
`.env.local`, or local `.keyit/` runtime caches.

Keyit does not create or update `.gitignore` for you. Add these
exclusions to the project's `.gitignore` before committing:

```text
.env
.env.*
!.env.example
```

By default, projects use the hosted relay at:

```text
https://relay.keyit.sh
```

Use `--relay-url` when pointing a project at another HTTP(S) relay,
such as a self-hosted one.

Check another relay explicitly with:

```bash
keyit relay check --relay-url https://relay.example.com
```

## Shell Completions

```bash
keyit completions zsh > ~/.zsh/completions/_keyit
keyit-relay completions zsh > ~/.zsh/completions/_keyit-relay
```

Supported shell names are provided by Clap, including `bash`, `zsh`,
`fish`, `powershell`, and `elvish`.

## Relay Operators

For the hosted relay container path, see
[`relay-container-deployment.md`](relay-container-deployment.md).

For production relay runtime settings, see
[`relay-production.md`](relay-production.md).

For publishing versioned releases, see [`release.md`](release.md).
