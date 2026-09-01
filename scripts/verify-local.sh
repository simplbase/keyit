#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="${TMPDIR:-/tmp}/keyit-verify-local.$$"
owner_project="$scratch/project"
owner_data="$scratch/owner-data"
member_data="$scratch/member-data"
relay_dir="$scratch/relay"

cleanup() {
  rm -rf "$scratch"
}
trap cleanup EXIT

mkdir -p "$owner_project" "$owner_data" "$member_data" "$relay_dir"

cd "$workspace_root"
cargo build --workspace --bins --locked

keyit="$workspace_root/target/debug/keyit"
common_env=(env KEYIT_KEY_STORE=file)
owner_env=(env KEYIT_KEY_STORE=file KEYIT_DATA_DIR="$owner_data")
member_env=(env KEYIT_KEY_STORE=file KEYIT_DATA_DIR="$member_data")

cd "$owner_project"
"${owner_env[@]}" "$keyit" init --project-label verify-local --relay-url file://local-verify
"${owner_env[@]}" "$keyit" env add development .env.local
printf 'API_KEY=verify-demo-token\nLOG_LEVEL=debug\n' > .env.local
"${owner_env[@]}" "$keyit" push development --summary "verify initial revision" --relay-dir "$relay_dir"
rm .env.local
"${owner_env[@]}" "$keyit" pull development --relay-dir "$relay_dir"
"${owner_env[@]}" "$keyit" whoami
"${owner_env[@]}" "$keyit" env list
"${owner_env[@]}" "$keyit" revision list development

invite_bundle="$("${owner_env[@]}" "$keyit" invite create --env development --expires-at 4102444800 --max-uses 1 | awk '/^  bundle:/ {print $2}')"
joining_device_id="$("${member_env[@]}" "$keyit" join "$invite_bundle" --env development --device-label verify-member | awk '/^Created join request for / {print $5}')"
owner_state="$(find "$owner_data/projects" -mindepth 1 -maxdepth 1 -type d | head -n 1)/.keyit"
member_state="$(find "$member_data/projects" -mindepth 1 -maxdepth 1 -type d | head -n 1)/.keyit"
mkdir -p "$owner_state/join-requests"
cp "$member_state/join-requests/$joining_device_id.keyit" "$owner_state/join-requests/$joining_device_id.keyit"
"${owner_env[@]}" "$keyit" approve "$joining_device_id" --role member
"${owner_env[@]}" "$keyit" revoke "$joining_device_id" --env development --reason "verification cleanup"

"${common_env[@]}" "$keyit" version

echo "Local verification workflow completed successfully."
