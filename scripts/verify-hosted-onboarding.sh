#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
relay_url="${KEYIT_VERIFY_RELAY_URL:-https://relay.keyit.sh}"
scratch="${TMPDIR:-/tmp}/keyit-verify-hosted-onboarding.$$"
owner_project="$scratch/owner-project"
joiner_project="$scratch/joiner-project"
owner_data="$scratch/owner-data"
joiner_data="$scratch/joiner-data"

cleanup() {
  rm -rf "$scratch"
}
trap cleanup EXIT

mkdir -p "$owner_project" "$joiner_project" "$owner_data" "$joiner_data"

keyit="${KEYIT_BIN:-}"
if [ -z "$keyit" ]; then
  cd "$workspace_root"
  cargo build --workspace --bins --locked
  keyit="$workspace_root/target/debug/keyit"
fi
owner_env=(env KEYIT_KEY_STORE=file KEYIT_DATA_DIR="$owner_data")
joiner_env=(env KEYIT_KEY_STORE=file KEYIT_DATA_DIR="$joiner_data")

echo "verify-hosted-onboarding: testing relay $relay_url"

"$keyit" relay check --relay-url "$relay_url"

cd "$owner_project"
"${owner_env[@]}" "$keyit" init --project-label hosted-onboarding --relay-url "$relay_url"
"${owner_env[@]}" "$keyit" env add development .env.local
printf 'API_KEY=hosted-onboarding-initial\nLOG_LEVEL=debug\n' > .env.local
"${owner_env[@]}" "$keyit" push development --summary "initial hosted onboarding revision"

cd "$owner_project"
invite_bundle="$("${owner_env[@]}" "$keyit" invite create --env development --expires-at 4102444800 --max-uses 1 | awk '/^  bundle:/ {print $2}')"
test -n "$invite_bundle"
test -f "$invite_bundle"

cd "$joiner_project"
test ! -e .keyit
joining_device_id="$("${joiner_env[@]}" "$keyit" join "$invite_bundle" --env development --device-label hosted-joiner | awk '/^Created join request for / {print $5}')"

cd "$owner_project"
"${owner_env[@]}" "$keyit" approve "$joining_device_id" --role member
printf '# HOSTED ONBOARDING\nAPI_KEY=hosted-onboarding-approved\nLOG_LEVEL=info\n' > .env.local
"${owner_env[@]}" "$keyit" push development --summary "grant hosted joiner access"

cd "$joiner_project"
"${joiner_env[@]}" "$keyit" pull development

grep -q '# HOSTED ONBOARDING' .env.local
grep -q 'API_KEY=hosted-onboarding-approved' .env.local
grep -q 'LOG_LEVEL=info' .env.local

echo "Hosted onboarding verification workflow completed successfully against $relay_url."
