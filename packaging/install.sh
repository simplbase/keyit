#!/usr/bin/env sh
set -eu

prefix="${PREFIX:-/usr/local}"
profile="${CARGO_PROFILE:-release}"

cargo build --workspace --bins --profile "$profile" --locked

install -d "$prefix/bin"
install "target/$profile/keyit" "$prefix/bin/keyit"
install "target/$profile/keyit-relay" "$prefix/bin/keyit-relay"

printf 'installed keyit to %s/bin/keyit\n' "$prefix"
printf 'installed keyit-relay to %s/bin/keyit-relay\n' "$prefix"
