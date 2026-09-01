#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
relay_url="${KEYIT_VERIFY_RELAY_URL:-https://relay.keyit.sh}"
scratch="${TMPDIR:-/tmp}/keyit-verify-hosted.$$"
owner_project="$scratch/project"
clone_project="$scratch/clone"
owner_data="$scratch/owner-data"
clone_data="$scratch/clone-data"

cleanup() {
  rm -rf "$scratch"
}
trap cleanup EXIT

mkdir -p "$owner_project" "$clone_project" "$owner_data" "$clone_data"

echo "verify-hosted-relay: testing relay $relay_url"

curl -fsS "$relay_url/healthz" >/dev/null
curl -fsS "$relay_url/readyz" >/dev/null

cd "$workspace_root"
cargo build --workspace --bins --locked

keyit="$workspace_root/target/debug/keyit"
owner_env=(env KEYIT_KEY_STORE=file KEYIT_DATA_DIR="$owner_data")
clone_env=(env KEYIT_KEY_STORE=file KEYIT_DATA_DIR="$clone_data")

cd "$owner_project"
"${owner_env[@]}" "$keyit" init --project-label hosted-verify --relay-url "$relay_url"
"${owner_env[@]}" "$keyit" env add development .env.local
printf '# HOSTED VERIFY\nAPI_KEY=hosted-verify-demo-token\nLOG_LEVEL=debug\n' > .env.local
"${owner_env[@]}" "$keyit" push development --summary "hosted relay verification"

cp "$owner_project/keyit.toml" "$clone_project/keyit.toml"
cp "$owner_data/device-signing.key" "$clone_data/device-signing.key"
cp "$owner_data/device-encryption.key" "$clone_data/device-encryption.key"

cd "$clone_project"
"${clone_env[@]}" "$keyit" pull development

grep -q '# HOSTED VERIFY' .env.local
grep -q 'API_KEY=hosted-verify-demo-token' .env.local
grep -q 'LOG_LEVEL=debug' .env.local

echo "Hosted relay verification workflow completed successfully against $relay_url."
