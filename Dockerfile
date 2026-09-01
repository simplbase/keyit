# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.95

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build -p keyit-relay --bin keyit-relay --release --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin keyit

COPY --from=builder /src/target/release/keyit-relay /usr/local/bin/keyit-relay

ENV KEYIT_RELAY_MODE=production
ENV KEYIT_RELAY_ROOT=/data/relay
ENV KEYIT_RELAY_ADDR=0.0.0.0:8787
ENV KEYIT_RELAY_RATE_LIMIT_PER_MINUTE=120

RUN mkdir -p /data/relay \
    && chown -R 10001:10001 /data

USER 10001:10001
VOLUME ["/data/relay"]
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8787/readyz || exit 1

ENTRYPOINT ["keyit-relay"]
CMD ["serve", "--print-config"]
