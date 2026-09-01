#!/usr/bin/env bash
# Installs a tagged Keyit release into a scratch prefix and runs hosted
# onboarding against it, to confirm a release candidate is safe to publish.
#
# Every step prints a timestamped progress line, and every network-bound
# step runs under a bounded wait with a periodic heartbeat, so this script
# can never sit silently and appear stuck: it either finishes or fails
# loudly within its timeout.
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${KEYIT_VERSION:-}"
relay_url="${KEYIT_VERIFY_RELAY_URL:-https://relay.keyit.sh}"
scratch="${TMPDIR:-/tmp}/keyit-verify-release-candidate.$$"
prefix="$scratch/prefix"

# Bounded-wait timeouts (seconds). Override via env if a slower network is
# expected.
install_timeout="${KEYIT_VERIFY_INSTALL_TIMEOUT:-180}"
onboarding_timeout="${KEYIT_VERIFY_ONBOARDING_TIMEOUT:-180}"
heartbeat_interval=10

log() {
  printf '[verify-release-candidate] %s %s\n' "$(date '+%H:%M:%S')" "$*" >&2
}

cleanup() {
  rm -rf "$scratch"
}
trap cleanup EXIT

# Runs "$@" in the background, killing it (and printing a heartbeat every
# $heartbeat_interval seconds while it runs) if it exceeds $1 seconds. This
# is a portable stand-in for GNU `timeout`, which is not available on every
# platform this script runs on (notably stock macOS).
run_bounded() {
  local limit="$1"
  shift
  local label="$1"
  shift

  log "starting: $label (bounded to ${limit}s)"
  "$@" &
  local pid=$!
  local waited=0

  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$limit" ]; then
      log "TIMEOUT after ${limit}s: $label — killing pid $pid"
      kill -TERM "$pid" 2>/dev/null || true
      sleep 1
      kill -KILL "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      log "error: '$label' did not complete within ${limit}s"
      return 124
    fi
    sleep 1
    waited=$((waited + 1))
    if [ "$((waited % heartbeat_interval))" -eq 0 ]; then
      log "... still running: $label (${waited}s/${limit}s elapsed)"
    fi
  done

  wait "$pid"
  local status=$?
  if [ "$status" -eq 0 ]; then
    log "done: $label (${waited}s)"
  else
    log "error: '$label' exited with status $status after ${waited}s"
  fi
  return "$status"
}

if [ -z "$version" ]; then
  echo "error: set KEYIT_VERSION to the release tag to verify, e.g. v1.0.0" >&2
  exit 1
fi

log "verifying release candidate $version against $relay_url"
mkdir -p "$prefix"

run_bounded "$install_timeout" "install release $version" \
  env PREFIX="$prefix" KEYIT_VERSION="$version" "$workspace_root/packaging/install-release.sh"

log "checking installed binary versions"
"$prefix/bin/keyit" version
"$prefix/bin/keyit-relay" version

run_bounded "$onboarding_timeout" "hosted onboarding verification" \
  env KEYIT_BIN="$prefix/bin/keyit" \
  KEYIT_VERIFY_RELAY_URL="$relay_url" \
  "$workspace_root/scripts/verify-hosted-onboarding.sh"

log "Release candidate $version verified against $relay_url."
