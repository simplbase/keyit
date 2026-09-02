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

# Hosted-relay account limits. Leave unset (or set to 0) to run this
# relay unrestricted — see "Hosted vs Self-Hosted Limits" below.
export KEYIT_RELAY_MAX_PROJECTS_PER_DEVICE=3
export KEYIT_RELAY_MAX_ENVIRONMENTS_PER_PROJECT=3
export KEYIT_RELAY_MAX_DEVICES_PER_PROJECT=5
export KEYIT_RELAY_INACTIVE_RETENTION_DAYS=30
```

Production mode requires an absolute storage root and an HTTPS public
URL. `keyit-relay` does not terminate TLS itself.

## Hosted vs Self-Hosted Limits

Hosted relay limits protect shared infrastructure. Self-hosted relay
operators set their own rules.

`keyit-relay` ships with five configurable account limits. They are
plain runtime configuration read at process start: no license checks,
no activation keys, no phone-home behavior.

| Environment variable | What it caps | Self-hosted default |
| --- | --- | --- |
| `KEYIT_RELAY_MAX_PROJECTS_PER_DEVICE` | Projects a single creator device may publish to this relay | unlimited |
| `KEYIT_RELAY_MAX_ENVIRONMENTS_PER_PROJECT` | Environments per project | unlimited |
| `KEYIT_RELAY_MAX_DEVICES_PER_PROJECT` | Active (approved, non-revoked) devices per project | unlimited |
| `KEYIT_RELAY_MAX_REVISIONS_PER_ENVIRONMENT` | Revision objects per environment | 10000 |
| `KEYIT_RELAY_INACTIVE_RETENTION_DAYS` | Days of inactivity before a project is *eligible* for retention cleanup | disabled |

For every limit above, leaving the variable unset keeps the
self-hosted default in the table, and explicitly setting it to `0`
always disables that limit — a self-hosted operator can raise or
disable any of them freely. A positive integer enforces that exact
cap. An unparsable value (not a non-negative integer) fails relay
startup with a clear error rather than silently falling back to a
default.

`KEYIT_RELAY_MAX_REVISIONS_PER_ENVIRONMENT` is the one exception to
"unset means unlimited": it already had a production-safe default
before the other hosted-relay limits existed, so leaving it unset
keeps that default (`10000`) instead of becoming unlimited. Set it to
`0` explicitly if a self-hosted deployment wants it uncapped.

`KEYIT_RELAY_INACTIVE_RETENTION_DAYS` is recorded and surfaced (e.g.
via `keyit-relay serve --print-config`) for configuration and
documentation purposes only. This relay does not yet implement
automated deletion of inactive projects — see "Known Limits" below —
so setting it does not, by itself, delete anything.

The example values above (`3` / `3` / `5` / `10000` / `30`) are for
Keyit's shared hosted relay. Use that relay to try the workflow. For
client work, production secrets, or stricter policy, run your own. The
CLI and protocol are the same either way: the CLI never enforces these
limits locally, it only displays the relay's error if a configured
relay limit is hit.

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
- maximum projects per creator device, environments per project, and
  active devices per project (see "Hosted vs Self-Hosted Limits" above);
- atomic writes through same-directory temporary files and rename;
- per-environment publish lock during latest-pointer conflict checks and
  writes, and an equivalent per-project lock guarding the account limits
  above against concurrent publishes.

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
- automated deletion of inactive projects: `KEYIT_RELAY_INACTIVE_RETENTION_DAYS`
  represents the policy in configuration, but no background job acts on
  it yet, since this filesystem backend has no safe cleanup path for
  deleting an entire project tree;
- multi-instance coordination for publish locks and nonce replay state;
- durable/shared metrics;
- automated backup/restore tests;
- hosted relay runbook and incident process.
