import Link from "next/link";
import type { ReactNode } from "react";

import { Available, ProtocolDefined } from "@/components/capability-status";
import { DeviceAuthDiagram, SyncFlowDiagram, TrustBoundaryDiagram } from "@/components/diagrams";
import { GITHUB_URL, PROTOCOL_SPEC_URL, CONTRIBUTING_URL } from "@/lib/layout.shared";
import { SectionHeader } from "@/components/section-header";
import { Terminal, type TerminalLine } from "@/components/terminal";

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
  { type: "command", text: "keyit diff production" },
  { type: "output", text: "  modified   STRIPE_WEBHOOK_SECRET" },
  { type: "blank" },
  { type: "command", text: "keyit push production --relay-url https://relay.keyit.sh" },
  { type: "output", text: "Created local encrypted revision kvr_9c2e41af… for production", tone: "success" },
  { type: "blank" },
  { type: "command", text: "keyit pull production --relay-url https://relay.keyit.sh" },
  { type: "output", text: "Materialized local revision kvr_9c2e41af… for production", tone: "success" },
];

const DEVICE_LINES: TerminalLine[] = [
  { type: "command", text: "keyit join kvi_7a30f1e2… --env production" },
  { type: "output", text: "Created join request for kvd_5e91a0c3…" },
  { type: "output", text: "  environments: 1" },
  { type: "blank" },
  { type: "command", text: "keyit approve kvd_5e91a0c3… --role admin" },
  { type: "output", text: "Approved device kvd_5e91a0c3…", tone: "success" },
  { type: "output", text: "  role:         admin" },
];

const ENV_LINES: TerminalLine[] = [
  { type: "command", text: "keyit env add production .env.production" },
  { type: "output", text: "Added Keyit environment production (kve_71cd0f88…)", tone: "success" },
  { type: "blank" },
  { type: "command", text: "keyit env list" },
  { type: "output", text: "Environment development (kve_1a2b3c9d…)" },
  { type: "output", text: "  local path:   .env.local" },
  { type: "output", text: "Environment production (kve_71cd0f88…)" },
  { type: "output", text: "  local path:   .env.production" },
];

const REVISION_LINES: TerminalLine[] = [
  { type: "command", text: "keyit revision list production" },
  { type: "output", text: "Revision kvr_9c2e41af…" },
  { type: "output", text: "  parent:     kvr_a10f2c9e…" },
  { type: "output", text: "  author:     kvd_3b7e0a12…" },
  { type: "output", text: "  summary:    rotate webhook secret" },
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

export default function HomePage() {
  return (
    <main>
      {/* 1. Hero */}
      <section className="border-t border-fd-border pt-14 pb-16 sm:pt-20 sm:pb-24">
        <div className="mx-auto grid w-full max-w-5xl gap-10 px-6 lg:grid-cols-[1.05fr_1fr] lg:items-center lg:gap-8">
          <div>
            <p className="mb-5 font-mono text-xs uppercase tracking-[0.08em] text-fd-muted-foreground">
              open-source · local-first · MIT/Apache-2.0
            </p>
            <h1 className="text-balance text-[2.15rem] font-semibold leading-[1.14] tracking-tight text-fd-foreground sm:text-4xl lg:text-[2.65rem]">
              Sync private project state across your team&apos;s machines — encrypted before it
              ever leaves yours.
            </h1>
            <p className="mt-5 max-w-xl text-[15.5px] leading-relaxed text-fd-muted-foreground sm:text-base">
              Keyit encrypts <code className="text-fd-foreground">.env</code> files locally with
              each device&apos;s own key, signs every change, and moves only ciphertext through a
              relay that never sees your secrets. A device gets access only when an Owner or
              Admin explicitly approves it — there&apos;s no email invite and no OAuth identity.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <CTALink href="/docs/getting-started/installation">Install Keyit</CTALink>
              <CTALink href={GITHUB_URL} variant="secondary">
                View on GitHub
              </CTALink>
            </div>
          </div>
          <Terminal label="production — 2 developers, 1 relay" lines={HERO_LINES} />
        </div>
      </section>

      {/* 2. The problem */}
      <Section id="the-problem">
        <SectionHeader
          id="the-problem-heading"
          index="01"
          eyebrow="Why this gets messy"
          title="Private project state doesn't stay in sync on its own."
        />
        <div className="grid gap-x-10 gap-y-3 text-[15px] leading-relaxed text-fd-muted-foreground sm:grid-cols-2">
          <p>— a teammate pastes a <code className="text-fd-foreground">.env</code> block into a chat thread to unblock someone</p>
          <p>— the copy on your machine is quietly a few keys behind theirs</p>
          <p>— a value gets rotated and someone has to remember who still needs the new one</p>
          <p>— nobody can say, with certainty, which revision a given machine is running</p>
          <p>— a project has development, staging, and production state to keep straight</p>
          <p>— revoking someone&apos;s laptop access doesn&apos;t rotate anything by itself</p>
        </div>
      </Section>

      {/* 3. How Keyit works */}
      <Section id="how-it-works">
        <SectionHeader
          id="how-it-works-heading"
          index="02"
          eyebrow="How Keyit works"
          title="Two devices, one relay that only ever sees ciphertext."
        />
        <SyncFlowDiagram />
      </Section>

      {/* 4. Explicit synchronization */}
      <Section id="explicit-sync">
        <div className="grid gap-10 lg:grid-cols-[0.9fr_1.1fr] lg:items-start lg:gap-12">
          <SectionHeader
            id="explicit-sync-heading"
            index="03"
            eyebrow="Explicit synchronization"
            title="Nothing syncs until you run a command."
            dek={
              <>
                Keyit has no background daemon and no invisible auto-sync.{" "}
                <code className="text-fd-foreground">status</code> and{" "}
                <code className="text-fd-foreground">diff</code> tell you exactly what state
                you&apos;re in before you touch anything; <code className="text-fd-foreground">push</code> and{" "}
                <code className="text-fd-foreground">pull</code> are the only two ways state moves.
              </>
            }
          />
          <div className="flex flex-col gap-4">
            <Terminal label="explicit sync" lines={SYNC_LINES} />
            <Available>
              <code>status</code>, <code>diff</code>, <code>push</code>, and <code>pull</code> are
              all real, working commands in the current CLI
            </Available>
          </div>
        </div>
      </Section>

      {/* 5. Device-based authorization */}
      <Section id="device-authorization">
        <SectionHeader
          id="device-authorization-heading"
          index="04"
          eyebrow="Device authorization"
          title="Access is granted to devices, by people — not by email."
          dek="Every device has its own Ed25519 signing identity, generated on first use. A new device requests access with an invite; an Owner or Admin approves it and picks its role explicitly. There's no account system underneath this — identity is cryptographic, not an email address."
        />
        <div className="grid gap-8 lg:grid-cols-[1.1fr_0.9fr] lg:items-center lg:gap-10">
          <DeviceAuthDiagram />
          <Terminal label="device authorization" lines={DEVICE_LINES} />
        </div>
        <p className="mt-6 max-w-2xl font-mono text-[13px] text-fd-muted-foreground">
          Roles: <span className="text-fd-foreground">Owner</span>,{" "}
          <span className="text-fd-foreground">Admin</span>,{" "}
          <span className="text-fd-foreground">Member</span> — an Owner or an Admin may approve a
          joining device.
        </p>
      </Section>

      {/* 6. Environments */}
      <Section id="environments">
        <div className="grid gap-10 lg:grid-cols-[0.9fr_1.1fr] lg:items-start lg:gap-12">
          <SectionHeader
            id="environments-heading"
            index="05"
            eyebrow="Environments"
            title="Development, staging, and production don't share a key."
            dek="Each environment gets its own genesis, its own encryption key, and its own revision history. A device authorized for development isn't automatically authorized for production — access and keys are scoped per environment, not per project."
          />
          <Terminal label="environments" lines={ENV_LINES} />
        </div>
      </Section>

      {/* 7. Relay trust model */}
      <Section id="relay-trust" className="bg-fd-muted/40">
        <SectionHeader
          id="relay-trust-heading"
          index="06"
          eyebrow="Relay trust model"
          title="The relay moves your state across the internet. It doesn't need to read it."
          dek="Getting an encrypted revision from one machine to another over the internet requires something in the middle. Keyit's relay stores and forwards signed, encrypted revisions — it has no key that can decrypt them, and no plaintext ever reaches it."
        />
        <TrustBoundaryDiagram />
      </Section>

      {/* 8. Signed revisions */}
      <Section id="signed-revisions">
        <div className="grid gap-10 lg:grid-cols-[0.9fr_1.1fr] lg:items-start lg:gap-12">
          <div>
            <SectionHeader
              id="signed-revisions-heading"
              index="07"
              eyebrow="History"
              title="Every push is a signed, append-only revision."
              dek="Each revision records its parent, its author device, and a non-secret summary — never values. It's real history, not an overwritten file, and it's already how every push and pull on this page works."
            />
            <div className="flex flex-col gap-2.5">
              <ProtocolDefined>
                the protocol&apos;s frozen rules describe rollback as creating a new revision rather
                than deleting history — there&apos;s no <code>keyit revision rollback</code> command yet
              </ProtocolDefined>
              <ProtocolDefined>
                conflict *detection* is real (a stale push is rejected); there&apos;s no guided
                resolve/merge command — today&apos;s flow is pull, edit by hand, push again
              </ProtocolDefined>
            </div>
          </div>
          <Terminal label="revision history" lines={REVISION_LINES} />
        </div>
      </Section>

      {/* 9. Open source */}
      <Section id="open-source">
        <SectionHeader
          id="open-source-heading"
          index="08"
          eyebrow="Open source"
          title="Inspectable, not just auditable in principle."
          dek="Keyit is source-available under a dual MIT/Apache-2.0 license. There's no separate paid tier of the protocol, and nothing here is a claim about adoption — read the code and the spec instead of taking either on faith."
        />
        <div className="flex flex-wrap gap-3">
          <CTALink href={GITHUB_URL} variant="secondary">
            GitHub
          </CTALink>
          <CTALink href={PROTOCOL_SPEC_URL} variant="secondary">
            Protocol spec
          </CTALink>
          <CTALink href="/docs/security" variant="secondary">
            Security model
          </CTALink>
          <CTALink href={CONTRIBUTING_URL} variant="secondary">
            Contributing
          </CTALink>
        </div>
      </Section>

      {/* 10. Final CTA */}
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
            <CTALink href={PROTOCOL_SPEC_URL} variant="secondary">
              Read the Protocol
            </CTALink>
          </div>
        </div>
      </Section>
    </main>
  );
}
