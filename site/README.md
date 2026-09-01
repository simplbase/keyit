# keyit.dev

The public website and documentation for [Keyit](../README.md), built with
Next.js (App Router) and [Fumadocs](https://fumadocs.dev).

This is a foundation pass: the documentation is real and derived from the
Rust workspace (`../crates`) and the frozen protocol spec
(`../docs/protocol/keyit-protocol-v1.md`), but the marketing homepage is a
placeholder shell — see `src/app/(home)/page.tsx`. Full homepage design
comes after the documentation IA has stabilized.

## Stack

- **Next.js 16** (App Router, Turbopack) + TypeScript
- **Tailwind CSS v4**
- **[Fumadocs](https://fumadocs.dev)** (`fumadocs-core` + `fumadocs-ui` +
  `fumadocs-mdx`) for the documentation shell, search, and MDX pipeline
- **Orama** search — self-hosted, built from the docs at request time, no
  external service or API key
- **[Geist](https://vercel.com/font)** (Sans + Mono) — self-hosted font
  files, no external font requests at build or run time
- No database, no CMS, no auth, no analytics. Content lives in Git as MDX.

## Running locally

```bash
cd site
npm install
npm run dev
```

Then open <http://localhost:3000>. `/docs` is the documentation; `/` is
the placeholder homepage shell.

```bash
npm run build   # production build (also type-checks)
npm run start   # serve the production build
npm run lint    # ESLint
```

## Content

- `content/docs/**` — every documentation page (MDX) and its `meta.json`
  nav ordering. Only sections with real, verified content are published;
  there is no stub-page scaffolding here anymore.
- `src/components/capability-status.tsx` — the `<Available>` /
  `<ProtocolDefined>` convention used throughout the docs to distinguish
  what the current `keyit` CLI actually implements from what's frozen in
  the protocol spec but not yet exposed.

## Source of truth

When writing or editing documentation:

1. `../docs/protocol/keyit-protocol-v1.md` is authoritative for frozen
   protocol behavior.
2. The Rust source (`../crates/keyit-cli`, `../crates/keyit-protocol`,
   `../crates/keyit-relay`) is authoritative for what's actually
   implemented — command names, flags, output text.
3. Existing docs/README examples are only a source of truth where they
   agree with the actual implementation; several didn't (see the
   foundation blueprint's decision log) and the docs here were written
   from source instead.

Never document a command that doesn't exist yet just because the
protocol describes the capability — mark it `<ProtocolDefined>` instead.
