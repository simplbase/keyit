# Try Keyit Locally

This guide runs Keyit without real secrets.

## Automated Local Verification

```bash
scripts/verify-local.sh
```

The script uses isolated temporary directories and
`KEYIT_KEY_STORE=file`, so it does not touch the user's normal Keyit
device identity or macOS Keychain entries.

It exercises:

- `keyit init`;
- `keyit env add`;
- encrypted `keyit push` through a filesystem relay directory;
- `keyit pull`;
- `keyit whoami`;
- `keyit env list`;
- `keyit revision list`;
- invite, join, approve, and revoke access records;
- `keyit version`.

The sample dotenv file contains only fake values. Command output is
expected to omit dotenv values; inspection commands report identifiers,
public keys, local paths, and revision metadata only.

## Manual Flow

For a smaller manual run:

```bash
export KEYIT_KEY_STORE=file
export KEYIT_DATA_DIR="$(mktemp -d)"
mkdir -p /tmp/keyit-demo
cd /tmp/keyit-demo

keyit init --project-label demo
keyit env add development .env.local
printf 'API_KEY=demo-token\nLOG_LEVEL=debug\n' > .env.local
keyit push development --summary "initial demo"
keyit whoami
keyit env list
keyit revision list development
```

Use fake values for local demos. Keyit's default output should remain
safe to paste into issue reports, but plaintext dotenv files are still
local secret material.

## Hosted Relay Verification

When the hosted relay (`relay.keyit.sh`) is intentionally online, run:

```bash
keyit relay check
scripts/verify-hosted-relay.sh
```

`keyit relay check` reports `/healthz` and `/readyz` status for the
default hosted relay. The verification script uses fake dotenv values, a
disposable local device key directory, and a disposable project. It
pushes an encrypted revision through the hosted HTTPS relay, then pulls
that revision into a second disposable checkout that contains only
`keyit.toml` plus copied test device keys.

The target relay can be overridden:

```bash
keyit relay check --relay-url https://relay.example.com
KEYIT_VERIFY_RELAY_URL=https://relay.example.com scripts/verify-hosted-relay.sh
```

## Hosted Onboarding Verification

To verify the hosted relay with two independent device identities, run:

```bash
scripts/verify-hosted-onboarding.sh
```

This creates an owner project and an empty second checkout with a
separate device key directory. The owner publishes an invite and creates
an invite bundle, the joining device bootstraps from that bundle and
publishes a join request. The owner then fetches and approves that
request, and the joining device pulls a revision encrypted for its
device.

The target relay can be overridden:

```bash
KEYIT_VERIFY_RELAY_URL=https://relay.example.com scripts/verify-hosted-onboarding.sh
```
