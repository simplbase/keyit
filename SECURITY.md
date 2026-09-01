# Security Policy

Keyit is security-sensitive software. It is designed to synchronize
private project state across approved developer machines through relay
infrastructure that is explicitly untrusted.

Keyit is currently private-beta software. It has not undergone an
external security audit and should not be used as the only control
protecting high-value production secrets.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in Keyit, please
report it privately rather than opening a public issue.

Preferred: open a [GitHub Security Advisory](../../security/advisories/new)
for this repository. This creates a private channel between you and the
maintainers before details become public.

Please include, where possible:

- a description of the vulnerability and its potential impact
- steps to reproduce, or a proof of concept
- the affected version, commit, or component

We will acknowledge reports as promptly as we can and coordinate a fix
and disclosure timeline with the reporter.

## Current Guarantees

Keyit's intended security boundary is:

- plaintext dotenv values stay on approved devices
- device private keys are stored outside project repositories
- relay storage is treated as readable by the relay operator
- relay requests are signed by device identities
- encrypted environment revisions are wrapped only for active authorized
  devices

Revocation prevents future access after the next owner/admin rotation
push. It cannot erase plaintext or wrapped keys that a revoked device
already received.
