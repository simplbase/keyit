# Keyit Relay Container Deployment

This document describes the minimal deployment path for the self-hosted
alpha relay on the shared Simplbase VPS.

The relay remains untrusted infrastructure. It stores public protocol
metadata and encrypted payload bytes only.

## Image

The repository builds a relay-only container image from the root
`Dockerfile`.

Local build:

```bash
docker build -t keyit-relay:local .
```

The image runs:

```bash
keyit-relay serve --print-config
```

and exposes the relay on port `8787` inside the container.

## GitHub Container Registry

The `Relay Image` workflow publishes:

```text
ghcr.io/<owner>/<repo>/keyit-relay:latest
ghcr.io/<owner>/<repo>/keyit-relay:sha-<commit>
```

`pull_request` builds are validation-only and are not pushed.

## Simplbase VPS Layout

On the VPS:

```bash
cd /opt/simplbase/projects/keyit
cp /path/to/deploy/simplbase/keyit/compose.yml compose.yml
cp /path/to/deploy/simplbase/keyit/.env.example .env
chmod 600 .env
mkdir -p data/relay backups
sudo chown -R 10001:10001 data
```

Set `KEYIT_RELAY_IMAGE` in `.env` to the GHCR image for the repository.

The relay container runs as UID `10001`, so the mounted relay data
directory must be writable by that UID.

## Caddy

The shared Caddy container must be attached to the same external Docker
network configured by `SIMPLBASE_PROXY_NETWORK`.

Routes: `relay.keyit.sh` is the canonical hosted relay hostname.

```caddyfile
relay.keyit.sh {
    reverse_proxy keyit-relay:8787
}
```

Only Caddy should expose public ports. The relay container should not
publish `8787` to the host.

## Start

```bash
docker compose pull
docker compose up -d
docker compose ps
```

Check through Caddy:

```bash
curl https://relay.keyit.sh/healthz
curl https://relay.keyit.sh/readyz
curl https://relay.keyit.sh/metrics
```

## Maintenance

Inspect storage:

```bash
docker compose exec keyit-relay keyit-relay maintenance inspect --root /data/relay
```

Dry-run cleanup:

```bash
docker compose exec keyit-relay keyit-relay maintenance cleanup --root /data/relay --dry-run
```

## Current Limit

This deployment uses the current filesystem relay backend. It is suitable
for a hardened single-node alpha relay. Multi-instance relay hosting
still needs a PostgreSQL or object-store backed relay store.
