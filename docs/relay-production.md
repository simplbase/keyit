# Relay Production Deployment

Keyit Relay remains untrusted infrastructure: it stores signed/public
metadata and encrypted payload bytes, never plaintext dotenv values or
unwrapped data-encryption keys.

This production deployment model assumes:

- TLS is terminated by a reverse proxy, load balancer, or managed
  ingress in front of `keyit-relay`;
- `keyit-relay` binds to a private interface or loopback address;
- the relay storage root is on durable, backed-up storage;
- `/healthz` is used for liveness, `/readyz` is used for readiness, and
  `/metrics` is scraped for basic counters.

## Runtime Environment

```bash
export KEYIT_RELAY_MODE=production
export KEYIT_RELAY_ROOT=/var/lib/keyit-relay
export KEYIT_RELAY_ADDR=127.0.0.1:8787
export KEYIT_RELAY_PUBLIC_URL=https://relay.keyit.sh

export KEYIT_RELAY_RATE_LIMIT_PER_MINUTE=120
export KEYIT_RELAY_MAX_HEADER_BYTES=65536
export KEYIT_RELAY_MAX_BODY_BYTES=2097152
export KEYIT_RELAY_MAX_AUTHORIZATION_BYTES=524288
export KEYIT_RELAY_MAX_REQUEST_PAYLOAD_BYTES=1572864
export KEYIT_RELAY_MAX_REVISION_METADATA_BYTES=262144
export KEYIT_RELAY_MAX_ENCRYPTED_PAYLOAD_BYTES=1048576
export KEYIT_RELAY_MAX_REVISIONS_PER_ENVIRONMENT=10000
```

Production mode requires an absolute storage root and an HTTPS public
URL. `keyit-relay` does not terminate TLS itself.

For container deployment through the shared Simplbase VPS, see
[`relay-container-deployment.md`](relay-container-deployment.md), which
also covers routing `relay.keyit.sh` to the relay container through
Caddy. The containerized relay should be reachable only from the
private Docker network behind Caddy.

## Service Command

```bash
keyit-relay serve --print-config
```

Equivalent flag-based form:

```bash
keyit-relay serve \
  --mode production \
  --root /var/lib/keyit-relay \
  --addr 127.0.0.1:8787 \
  --public-url https://relay.keyit.sh \
  --rate-limit-per-minute 120
```

## Probes

```bash
curl http://127.0.0.1:8787/healthz
curl http://127.0.0.1:8787/readyz
curl http://127.0.0.1:8787/metrics
```

`/healthz` only proves the process can answer HTTP. `/readyz` also
checks that the storage root can be created and written. `/metrics`
returns in-process text counters for requests, bytes, publishes,
fetches, status counts, and rate-limit hits.

## Storage Inspection

Before serving from a restored backup, inspect the relay root:

```bash
keyit-relay maintenance inspect --root /var/lib/keyit-relay
```

The command reports object counts and verifies that revision envelopes
match their storage paths and still have matching payload sidecars.

## Storage Hardening

The filesystem backend now enforces:

- maximum revision metadata size;
- maximum encrypted payload size;
- maximum revisions per project/environment;
- atomic writes through same-directory temporary files and rename;
- per-environment publish lock during latest-pointer conflict checks and
  writes.

Backups should include the entire `KEYIT_RELAY_ROOT`. The relay does not
currently implement revision object garbage collection or retention
windows.

## Abuse Controls

The relay rejects oversized request headers, request bodies,
authorization envelopes, relay payload envelopes, revision metadata, and
encrypted payloads. It also applies an in-process fixed-window request
limit per peer IP.

For internet exposure, keep reverse-proxy controls in front of the
relay:

- TLS termination;
- request timeout;
- connection limit;
- body-size limit matching or below `KEYIT_RELAY_MAX_BODY_BYTES`;
- IP reputation or upstream DDoS protection;
- access logs that do not record request bodies.

## Retention Cleanup

Run cleanup periodically:

```bash
keyit-relay maintenance cleanup --root /var/lib/keyit-relay --dry-run
keyit-relay maintenance cleanup --root /var/lib/keyit-relay
```

Cleanup removes expired replay nonce files, leftover temporary files,
and stale publish locks. TTLs can be tuned:

```bash
--nonce-ttl-seconds 604800
--temp-ttl-seconds 86400
--stale-lock-ttl-seconds 900
```

## Known Limits

This model is enough for a hardened self-hosted alpha relay, but not the
final hosted Keyit service. Known limits:

- object-store or database-backed storage;
- revision retention/garbage-collection policy;
- multi-instance coordination for publish locks and nonce replay state;
- durable/shared metrics;
- automated backup/restore tests;
- hosted relay runbook and incident process.
