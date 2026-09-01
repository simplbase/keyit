# Contributing to Keyit

Thanks for your interest in Keyit. The project is early and
security-sensitive, so please discuss substantial behavior changes before
sending a large pull request.

## Prerequisites

- A stable Rust toolchain. The exact version is pinned in
  [`rust-toolchain.toml`](rust-toolchain.toml); `rustup` will pick it up
  automatically.
- The `rustfmt` and `clippy` components (also declared in
  `rust-toolchain.toml` and installed automatically by `rustup`).

## Workspace layout

This is a single Cargo workspace with three crates:

| Crate             | Purpose                                              |
| ------------------ | ----------------------------------------------------- |
| `keyit-protocol`  | Core domain/protocol implementation. No dependency on the CLI or relay. |
| `keyit-cli`       | Developer-facing CLI. Depends on `keyit-protocol`.   |
| `keyit-relay`     | Untrusted relay service. Depends on `keyit-protocol`.|

Keep that dependency direction intact: protocol code must never import
from `keyit-cli` or `keyit-relay`.

## Common commands

Run these from the repository root.

```sh
# Build everything
cargo build --workspace --all-targets

# Run all tests
cargo test --workspace

# Format code
cargo fmt --all

# Check formatting without changing files (what CI runs)
cargo fmt --all -- --check

# Lint (what CI runs — warnings are treated as errors)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run the CLI
cargo run -p keyit-cli -- --help

# Run the relay binary
cargo run -p keyit-relay -- --help
```

## Before opening a pull request

Please make sure `cargo fmt --all -- --check`, `cargo clippy --workspace
--all-targets --all-features -- -D warnings`, `cargo build --workspace
--all-targets`, and `cargo test --workspace` all pass locally — this is
exactly what CI checks. Add tests for new behavior where practical.

## Architecture

Read [`docs/architecture.md`](docs/architecture.md) before changing the
dependency direction, protocol record model, key handling, relay API, or
`.keyit/` layout.

## Security-sensitive changes

Keyit is security-sensitive software. Please do not open public issues
or pull requests for suspected vulnerabilities — see
[`SECURITY.md`](SECURITY.md) for how to report them privately.
