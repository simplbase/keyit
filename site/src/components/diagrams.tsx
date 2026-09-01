import type { CSSProperties, ReactNode } from "react";

/**
 * Keyit diagram primitives — HTML/CSS + small inline SVG connectors, not
 * raster illustrations or one big canvas. Built as flex layouts that
 * reflow (row → column) at small widths rather than a fixed-viewBox SVG
 * that just shrinks until the labels stop being legible.
 *
 * Shared visual language across all three: solid border = a real device
 * or state; dashed border = untrusted, in-transit, or not-yet-real
 * (`--keyit-protocol`); one stroke weight (`--keyit-line`) throughout.
 */

function DiagramFrame({
  children,
  label,
}: {
  children: ReactNode;
  label: string;
}) {
  return (
    <figure
      className="keyit-surface border border-fd-border bg-fd-card px-5 py-7 sm:px-8 sm:py-9"
      aria-label={label}
    >
      {children}
    </figure>
  );
}

function Node({
  title,
  detail,
  tone = "solid",
}: {
  title: string;
  detail?: string;
  tone?: "solid" | "dashed";
}) {
  return (
    <div
      className="keyit-surface flex min-w-[9.5rem] flex-1 flex-col items-center gap-1 border px-4 py-3.5 text-center sm:min-w-[10.5rem]"
      style={{
        borderStyle: tone === "dashed" ? "dashed" : "solid",
        borderColor: tone === "dashed" ? "var(--keyit-protocol-border)" : "var(--color-fd-border)",
        borderWidth: "var(--keyit-line)",
        background: tone === "dashed" ? "var(--keyit-protocol-soft)" : "var(--color-fd-background)",
      }}
    >
      <span className="font-mono text-[13px] font-medium text-fd-foreground">{title}</span>
      {detail ? (
        <span className="font-mono text-[11px] leading-snug text-fd-muted-foreground">{detail}</span>
      ) : null}
    </div>
  );
}

function Connector({ label }: { label: string }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-1.5 py-2 sm:py-0" aria-hidden="true">
      {/* horizontal on row layout */}
      <svg
        className="hidden h-3 w-full min-w-[2.5rem] text-fd-muted-foreground sm:block"
        viewBox="0 0 100 12"
        preserveAspectRatio="none"
      >
        <line
          x1="0"
          y1="6"
          x2="94"
          y2="6"
          stroke="currentColor"
          strokeWidth="1.5"
          className="keyit-draw"
          style={{ "--keyit-dash": 100 } as CSSProperties}
        />
        <path d="M94 2L100 6L94 10" fill="none" stroke="currentColor" strokeWidth="1.5" />
      </svg>
      {/* vertical on column layout */}
      <svg className="h-8 w-3 text-fd-muted-foreground sm:hidden" viewBox="0 0 12 40" preserveAspectRatio="none">
        <line
          x1="6"
          y1="0"
          x2="6"
          y2="34"
          stroke="currentColor"
          strokeWidth="1.5"
          className="keyit-draw"
          style={{ "--keyit-dash": 40 } as CSSProperties}
        />
        <path d="M2 34L6 40L10 34" fill="none" stroke="currentColor" strokeWidth="1.5" />
      </svg>
      <span className="max-w-[8rem] text-center font-mono text-[10.5px] leading-tight text-fd-muted-foreground">
        {label}
      </span>
    </div>
  );
}

/** "How Keyit works" — the homepage's central schematic. */
export function SyncFlowDiagram() {
  return (
    <DiagramFrame label="Diagram: how a Keyit push and pull moves between two devices through the relay">
      <div className="flex flex-col items-stretch gap-0 sm:flex-row sm:items-center">
        <Node title="Developer A" detail="keyit push · encrypts locally" />
        <Connector label="encrypted revision only" />
        <Node title="Relay" detail="untrusted · stores ciphertext" tone="dashed" />
        <Connector label="encrypted revision only" />
        <Node title="Developer B" detail="keyit pull · decrypts locally" />
      </div>
      <p className="mt-6 max-w-md text-[13px] leading-relaxed text-fd-muted-foreground sm:mt-8">
        The relay never receives a plaintext value — only a signed, encrypted
        revision. Encryption and decryption both happen on-device, on either
        end.
      </p>
    </DiagramFrame>
  );
}

/** Relay trust model: the diagram Keyit's core security claim depends on. */
export function TrustBoundaryDiagram() {
  return (
    <DiagramFrame label="Diagram: the relay trust boundary — encrypted revisions cross it, plaintext never does">
      <div className="flex flex-col items-stretch gap-0 sm:flex-row sm:items-stretch">
        <div className="flex flex-1 items-center justify-center">
          <Node title="Your machine" detail="plaintext .env lives here" />
        </div>

        <div className="flex flex-[1.3] flex-col items-center justify-center gap-3 py-4 sm:py-0">
          <div
            className="keyit-surface relative flex w-full flex-col items-center gap-2 border px-4 py-5 text-center"
            style={{
              borderStyle: "dashed",
              borderWidth: "var(--keyit-line)",
              borderColor: "var(--keyit-protocol-border)",
              background: "var(--keyit-protocol-soft)",
            }}
          >
            <span className="font-mono text-[10.5px] uppercase tracking-[0.08em] text-fd-muted-foreground">
              untrusted boundary
            </span>
            <span className="font-mono text-[13px] font-medium text-fd-foreground">Relay</span>
            <span className="font-mono text-[11px] text-fd-muted-foreground">
              kvr_9c2e41af&hellip;.bin
              <br />
              (ciphertext, signed, opaque)
            </span>
          </div>
        </div>

        <div className="flex flex-1 items-center justify-center">
          <Node title="Their machine" detail="plaintext .env materializes here" />
        </div>
      </div>
      <p className="mt-6 max-w-lg text-[13px] leading-relaxed text-fd-muted-foreground sm:mt-8">
        Keyit needs a relay to move revisions across the internet — but the
        relay only ever holds what&apos;s inside the dashed line: an encrypted,
        signed payload it can store and forward without being able to read
        it.
      </p>
    </DiagramFrame>
  );
}

/** Device authorization — join → pending → Owner/Admin approval. */
export function DeviceAuthDiagram() {
  return (
    <DiagramFrame label="Diagram: a new device requests access, then an Owner or Admin approves it">
      <div className="flex flex-col items-stretch gap-0 sm:flex-row sm:items-center">
        <Node title="New device" detail="keyit join <invite-id>" />
        <Connector label="pending approval" />
        <Node title="Pending" detail="visible, not yet authorized" tone="dashed" />
        <Connector label="keyit approve --role" />
        <Node title="Authorized" detail="Owner or Admin approved it" />
      </div>
    </DiagramFrame>
  );
}
