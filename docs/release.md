# Keyit Release Flow

Keyit releases are published from Git tags.

## Version Tag

Use semantic version tags with a leading `v`:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Pushing the tag starts the `Release` workflow.

## Release Artifacts

The workflow builds and uploads:

```text
keyit-vX.Y-x86_64-unknown-linux-gnu.tar.gz
keyit-vX.Y-x86_64-apple-darwin.tar.gz
keyit-vX.Y-aarch64-apple-darwin.tar.gz
keyit-vX.Y-x86_64-pc-windows-msvc.zip
SHA256SUMS
```

Each archive contains:

```text
keyit
keyit-relay
README.md
LICENSE
```

Windows archives contain `keyit.exe` and `keyit-relay.exe`.

## Installer

The Unix installer downloads a GitHub Release archive, verifies it
against `SHA256SUMS`, and installs both binaries:

```bash
curl -fsSL https://raw.githubusercontent.com/simplbase/keyit/main/packaging/install-release.sh | sh
```

Set `KEYIT_VERSION` to install a specific tag:

```bash
curl -fsSL https://raw.githubusercontent.com/simplbase/keyit/main/packaging/install-release.sh | KEYIT_VERSION=v1.0.0 sh
```

## Homebrew Tap

Keyit is published through the Simplbase Homebrew tap:

```bash
brew tap simplbase/tap
brew install keyit
```

After publishing a new Keyit release, update:

```text
https://github.com/simplbase/homebrew-tap/blob/main/Formula/keyit.rb
```

The formula must point to the new macOS and Linux release archives and
their matching SHA-256 digests.

## Relay Image

The existing `Relay Image` workflow also runs on `v*` tags and publishes
the relay container image to GHCR.

## Release Candidate Smoke

After the GitHub Release assets are available for a tag, verify the
installer and hosted onboarding path from the downloaded binaries:

```bash
KEYIT_VERSION=v1.0.0 scripts/verify-release-candidate.sh
```

This installs the tagged release into a temporary prefix, runs both
binary version commands, then runs hosted onboarding against
`https://relay.keyit.sh` using the installed `keyit` binary. Override
with `KEYIT_VERIFY_RELAY_URL` to verify against a different relay
(e.g. a self-hosted deployment) instead.
