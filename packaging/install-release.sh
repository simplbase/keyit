#!/usr/bin/env sh
set -eu

repo="${KEYIT_REPO:-simplbase/keyit}"
version="${KEYIT_VERSION:-latest}"
prefix="${PREFIX:-$HOME/.local}"

info() {
  printf 'keyit-install: %s\n' "$*" >&2
}

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'error: required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $2}'
  else
    printf 'error: shasum, sha256sum, or openssl is required for checksum verification\n' >&2
    exit 1
  fi
}

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os:$arch" in
    Linux:x86_64 | Linux:amd64)
      printf 'x86_64-unknown-linux-gnu'
      ;;
    Darwin:x86_64)
      printf 'x86_64-apple-darwin'
      ;;
    Darwin:arm64 | Darwin:aarch64)
      printf 'aarch64-apple-darwin'
      ;;
    *)
      printf 'error: unsupported platform: %s/%s\n' "$os" "$arch" >&2
      exit 1
      ;;
  esac
}

latest_version() {
  curl --fail --silent --show-error --location \
    --retry 3 --retry-delay 2 \
    --connect-timeout 15 --max-time 60 \
    "https://api.github.com/repos/$repo/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
    | head -n 1
}

download() {
  url="$1"
  output="$2"

  curl --fail --show-error --location \
    --retry 3 --retry-delay 2 \
    --connect-timeout 15 --max-time 300 \
    --output "$output" \
    "$url"
}

need awk
need curl
need sed
need tar

target="${KEYIT_TARGET:-$(detect_target)}"
if [ "$version" = "latest" ]; then
  info "resolving latest release for $repo"
  version="$(latest_version)"
fi
if [ -z "$version" ]; then
  printf 'error: could not resolve Keyit release version\n' >&2
  exit 1
fi

asset="keyit-${version}-${target}.tar.gz"
base_url="https://github.com/$repo/releases/download/$version"
tmp="${TMPDIR:-/tmp}/keyit-install.$$"

cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

mkdir -p "$tmp"
cd "$tmp"

info "installing $repo $version for $target"
info "downloading $asset"
download "$base_url/$asset" "$asset"
info "downloading SHA256SUMS"
download "$base_url/SHA256SUMS" SHA256SUMS

expected="$(grep " $asset\$" SHA256SUMS | awk '{print $1}')"
if [ -z "$expected" ]; then
  printf 'error: checksum entry not found for %s\n' "$asset" >&2
  exit 1
fi
info "verifying checksum"
actual="$(sha256 "$asset")"
if [ "$expected" != "$actual" ]; then
  printf 'error: checksum mismatch for %s\n' "$asset" >&2
  exit 1
fi

info "extracting archive"
tar -xzf "$asset"

info "installing binaries to $prefix/bin"
install -d "$prefix/bin"
install "keyit-${version}-${target}/keyit" "$prefix/bin/keyit"
install "keyit-${version}-${target}/keyit-relay" "$prefix/bin/keyit-relay"

printf 'installed keyit %s to %s/bin/keyit\n' "$version" "$prefix"
printf 'installed keyit-relay %s to %s/bin/keyit-relay\n' "$version" "$prefix"
