import Link from "next/link";
import type { ReactNode } from "react";

import { Available, ProtocolDefined } from "@/components/capability-status";
import { SyncFlowDiagram, TrustBoundaryDiagram } from "@/components/diagrams";
import { ResourceHub, type ResourceGroup } from "@/components/resource-hub";
import { SectionHeader } from "@/components/section-header";
import { Terminal, type TerminalLine } from "@/components/terminal";
import { VersionPill } from "@/components/version-pill";
import {
  ARCHITECTURE_URL,
  CONTRIBUTING_URL,
  DOCKER_IMAGE_URL,
  GITHUB_URL,
  LICENSE_URL,
  PROTOCOL_SPEC_URL,
  RELAY_DEPLOYMENT_URL,
  RELAY_PRODUCTION_URL,
  SECURITY_POLICY_URL,
  TRY_LOCAL_URL,
} from "@/lib/layout.shared";

/**
 * Keyit homepage.
 *
 * Every command and output line below must stay verified against
 * `keyit-cli/src/main.rs` (the `run_*_command` functions and their
 * `println!` text) — not README examples, not the protocol spec's
 * prose. Where a section touches something the protocol defines but
 * the CLI doesn't yet implement (rollback, guided conflict resolution),
 * it says so with `<ProtocolDefined>` rather than implying it works.
 */

const HERO_LINES: TerminalLine[] = [
  { type: "command", text: "keyit diff production" },
  { type: "output", text: "modified   STRIPE_WEBHOOK_SECRET" },
  { type: "output", text: "added      SENTRY_DSN" },
  { type: "blank" },
  {
    type: "command",
    text: 'keyit push production --summary "rotate webhook secret" --relay-url https://relay.keyit.sh',
  },
  {
    type: "output",
    text: "Created local encrypted revision kvr_9c2e41af… for production (kve_71cd0f88…)",
  },
  { type: "output", text: "  keys:     14" },
  { type: "output", text: "  relay:    published to https://relay.keyit.sh", tone: "success" },
];

const SYNC_LINES: TerminalLine[] = [
  { type: "command", text: "keyit status production" },
  { type: "output", text: "  latest:     kvr_a10f2c9e…" },
  { type: "output", text: "  local base: kvr_a10f2c9e…" },
  { type: "output", text: "  state:      local file present, 14 keys parsed" },
  { type: "blank" },
  { type: "command", text: "keyit pull production --relay-url https://relay.keyit.sh" },
  { type: "output", text: "Materialized local revision kvr_9c2e41af… for production", tone: "success" },
];

const RESOURCE_GROUPS: ResourceGroup[] = [
  {
    title: "Get started",
    links: [
      { label: "Install", href: "/docs/getting-started/installation" },
      { label: "Quickstart", href: "/docs/getting-started/quickstart" },
      { label: "Try local", href: TRY_LOCAL_URL, external: true },
    ],
  },
  {
    title: "Operate",
    links: [
      { label: "Relay deployment", href: RELAY_DEPLOYMENT_URL, external: true },
      { label: "Production relay notes", href: RELAY_PRODUCTION_URL, external: true },
      { label: "Docker image", href: DOCKER_IMAGE_URL, external: true },
    ],
  },
  {
    title: "Understand",
    links: [
      { label: "Architecture", href: ARCHITECTURE_URL, external: true },
      { label: "Security model", href: "/docs/security" },
      { label: "Protocol spec", href: PROTOCOL_SPEC_URL, external: true },
    ],
  },
  {
    title: "Reference",
    links: [
      { label: "CLI", href: "/docs/reference/cli" },
      { label: "Configuration", href: "/docs/reference/configuration" },
      { label: "File formats", href: "/docs/reference/file-formats" },
    ],
  },
  {
    title: "Project",
    links: [
      { label: "GitHub", href: GITHUB_URL, external: true },
      { label: "License (Apache-2.0)", href: LICENSE_URL, external: true },
      { label: "Contributing", href: CONTRIBUTING_URL, external: true },
      { label: "Security policy", href: SECURITY_POLICY_URL, external: true },
    ],
  },
];

function Section({
  id,
  className,
  children,
}: {
  id: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section
      id={id}
      aria-labelledby={`${id}-heading`}
      className={`border-t border-fd-border py-16 sm:py-20 ${className ?? ""}`}
    >
      <div className="mx-auto w-full max-w-5xl px-6">{children}</div>
    </section>
  );
}

function CTALink({
  href,
  children,
  variant = "primary",
}: {
  href: string;
  children: ReactNode;
  variant?: "primary" | "secondary";
}) {
  return (
    <Link
      href={href}
      className={
        variant === "primary"
          ? "keyit-surface inline-flex items-center justify-center border border-fd-primary bg-fd-primary px-4 py-2.5 font-mono text-sm font-medium text-fd-primary-foreground transition-opacity hover:opacity-90 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-fd-ring"
          : "keyit-surface inline-flex items-center justify-center border border-fd-border px-4 py-2.5 font-mono text-sm font-medium text-fd-foreground transition-colors hover:bg-fd-accent focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-fd-ring"
      }
    >
      {children}
    </Link>
  );
}

function RelayCard({
  eyebrow,
  title,
  body,
  links,
}: {
  eyebrow: string;
  title: string;
  body: ReactNode;
  links: { label: string; href: string }[];
}) {
  return (
    <div className="keyit-surface flex flex-col gap-3 border border-fd-border bg-fd-card px-5 py-6 sm:px-6 sm:py-7">
      <span className="font-mono text-[11px] uppercase tracking-[0.08em] text-fd-muted-foreground">
        {eyebrow}
      </span>
      <h3 className="font-mono text-[15px] font-medium text-fd-foreground">{title}</h3>
      <p className="text-[14px] leading-relaxed text-fd-muted-foreground">{body}</p>
      {links.length > 0 ? (
        <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1.5">
          {links.map((link) => (
            <a
              key={link.href}
              href={link.href}
              target="_blank"
              rel="noreferrer"
              className="font-mono text-[12.5px] text-fd-primary underline decoration-fd-primary/30 underline-offset-4 hover:decoration-fd-primary"
            >
              {link.label} ↗
            </a>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export default function HomePage() {
  return (
    <main>
      {/* 1. Hero — "Keyit" has to be unmistakable in the first viewport. */}
      <section className="border-t border-fd-border pt-14 pb-16 sm:pt-20 sm:pb-24">
        <div className="mx-auto grid w-full max-w-5xl gap-10 px-6 lg:grid-cols-[1.05fr_1fr] lg:items-center lg:gap-8">
          <div>
            <p className="mb-5 font-mono text-xs uppercase tracking-[0.08em] text-fd-muted-foreground">
              open-source · local-first · Apache-2.0
            </p>
            <h1 className="text-balance text-[2.3rem] font-semibold leading-[1.1] tracking-tight text-fd-foreground sm:text-[2.6rem] lg:text-[2.9rem]">
              Keyit is encrypted <code className="text-fd-primary">.env</code> sync for teams.
            </h1>
            <p className="mt-5 max-w-xl text-[15.5px] leading-relaxed text-fd-muted-foreground sm:text-base">
              No secrets manager account. No email invites. No vault to stand up. Each device
              signs and encrypts locally, and the relay in the middle only ever moves ciphertext
              it can&apos;t read.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <CTALink href="/docs/getting-started/installation">Install</CTALink>
              <CTALink href="/docs" variant="secondary">
                Read docs
              </CTALink>
              <CTALink href="#relay" variant="secondary">
                Run your own relay
              </CTALink>
              <CTALink href={GITHUB_URL} variant="secondary">
                GitHub
              </CTALink>
            </div>
          </div>
          <Terminal label="production — 2 developers, 1 relay" lines={HERO_LINES} />
        </div>
      </section>

      {/* 2. Hosted relay or your own */}
      <Section id="relay">
        <SectionHeader
          id="relay-heading"
          index="01"
          eyebrow="Hosted or self-hosted"
          title="Use the hosted relay to try Keyit fast. Run your own when the secrets are real."
          dek="Either way the trust model doesn't change: the relay stores and forwards signed, encrypted revisions. It has no key that can open them, so there's nothing sensitive for it to leak even if it's fully compromised."
        />
        <div className="grid gap-4 sm:grid-cols-2">
          <RelayCard
            eyebrow="Default"
            title="Hosted — relay.keyit.sh"
            body="Zero setup. No signup. keyit init works immediately against it. A reasonable default for trying Keyit and for lower-stakes projects."
            links={[]}
          />
          <RelayCard
            eyebrow="Your infrastructure"
            title="Self-hosted"
            body="Run the same keyit-relay binary or container yourself — the right call for client work, production secrets, or a compliance requirement the hosted relay can't satisfy. The source is right here."
            links={[
              { label: "Relay deployment", href: RELAY_DEPLOYMENT_URL },
              { label: "Production notes", href: RELAY_PRODUCTION_URL },
            ]}
          />
        </div>
        <div className="mt-6">
          <TrustBoundaryDiagram />
        </div>
      </Section>

      {/* 3. Resource hub + version-aware docs entry */}
      <Section id="resources">
        <div className="mb-8 flex flex-wrap items-end justify-between gap-4 sm:mb-10">
          <SectionHeader
            id="resources-heading"
            index="02"
            eyebrow="Documentation"
            title="Everything, linked directly."
            className="mb-0"
          />
          <div className="mb-1 flex items-center gap-3">
            <VersionPill />
            <Link
              href="/docs"
              className="font-mono text-[13px] text-fd-primary underline decoration-fd-primary/30 underline-offset-4 hover:decoration-fd-primary"
            >
              Browse the docs →
            </Link>
          </div>
        </div>
        <ResourceHub groups={RESOURCE_GROUPS} />
      </Section>

      {/* 4. How it works — concise on purpose; the docs cover the rest. */}
      <Section id="how-it-works" className="bg-fd-muted/40">
        <SectionHeader
          id="how-it-works-heading"
          index="03"
          eyebrow="How it works"
          title="Four ideas. That's the whole model."
        />
        <div className="grid gap-x-10 gap-y-8 sm:grid-cols-2">
          <div>
            <h3 className="mb-2 font-mono text-[13px] font-medium text-fd-foreground">
              Device identity
            </h3>
            <p className="text-[14px] leading-relaxed text-fd-muted-foreground">
              Every device generates its own Ed25519 signing key and X25519 key-agreement key on
              first use, kept in the OS Keychain where available. There are no Keyit user
              accounts — a device joins a project only when an existing Owner or Admin approves
              it by device, not by email.
            </p>
          </div>
          <div>
            <h3 className="mb-2 font-mono text-[13px] font-medium text-fd-foreground">
              Encrypted revisions
            </h3>
            <p className="text-[14px] leading-relaxed text-fd-muted-foreground">
              Every environment has its own random encryption key. A push encrypts the mapped
              dotenv file with that key and appends a signed revision recording its parent and
              author — real history, not an overwritten file.
            </p>
          </div>
          <div>
            <h3 className="mb-2 font-mono text-[13px] font-medium text-fd-foreground">
              Explicit push &amp; pull
            </h3>
            <p className="text-[14px] leading-relaxed text-fd-muted-foreground">
              No background daemon, no invisible auto-sync. <code>status</code> and{" "}
              <code>diff</code> show exactly what state you&apos;re in; <code>push</code> and{" "}
              <code>pull</code> are the only two ways state moves, and a stale push is rejected
              rather than silently overwriting someone else&apos;s change.
            </p>
          </div>
          <div>
            <h3 className="mb-2 font-mono text-[13px] font-medium text-fd-foreground">
              Relay trust boundary
            </h3>
            <p className="text-[14px] leading-relaxed text-fd-muted-foreground">
              The relay above only ever holds what&apos;s on the far side of that dashed line: an
              encrypted, signed payload it can store and forward without being able to read it —
              hosted or self-hosted, no exceptions.
            </p>
          </div>
        </div>

        <div className="mt-10 grid gap-8 lg:grid-cols-[1.1fr_0.9fr] lg:items-center lg:gap-10">
          <SyncFlowDiagram />
          <Terminal label="explicit sync" lines={SYNC_LINES} />
        </div>

        <div className="mt-8 flex flex-col gap-2.5">
          <Available>
            device identity, push, pull, status, and diff are all real, shipped commands
          </Available>
          <ProtocolDefined>
            rollback and guided conflict resolution are defined in the frozen protocol spec but
            not yet exposed by the CLI — today&apos;s flow for a conflict is pull, edit by hand,
            push again
          </ProtocolDefined>
        </div>
      </Section>

      {/* 5. Final CTA */}
      <Section id="get-started" className="pb-24">
        <div className="mx-auto max-w-2xl text-center">
          <h2
            id="get-started-heading"
            className="text-balance text-2xl font-semibold tracking-tight text-fd-foreground sm:text-[1.7rem]"
          >
            Keyit runs on your machines. Start on one.
          </h2>
          <p className="mx-auto mt-3 max-w-md text-[15px] leading-relaxed text-fd-muted-foreground">
            The quickstart takes you from an empty directory to a pushed and pulled encrypted
            revision with no relay and no second device required.
          </p>
          <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
            <CTALink href="/docs/getting-started/installation">Install Keyit</CTALink>
            <CTALink href="/docs/getting-started/quickstart" variant="secondary">
              Read the Quickstart
            </CTALink>
          </div>
        </div>
      </Section>
    </main>
  );
}
