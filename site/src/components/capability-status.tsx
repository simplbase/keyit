import type { ReactNode } from "react";

/**
 * The Available-now / Protocol-defined convention: never document a
 * command that doesn't exist yet as if it does.
 *
 * - `Available`         — implemented today in keyit-cli / keyit-relay.
 * - `ProtocolDefined`    — frozen in docs/protocol/keyit-protocol-v1.md,
 *                          but not yet exposed by the current CLI.
 *
 * Deliberately a small inline label, not a warning banner — this marks a
 * fact about the product, not a problem with the page.
 */
function StatusBadge({
  tone,
  label,
  children,
}: {
  tone: "available" | "protocol";
  label: string;
  children?: ReactNode;
}) {
  return (
    <span
      className="not-prose my-3 inline-flex items-center gap-2 rounded-sm border px-2.5 py-1 text-xs font-medium"
      style={
        tone === "available"
          ? {
              borderColor: "var(--keyit-signal-border)",
              color: "var(--keyit-signal)",
              backgroundColor: "var(--keyit-signal-soft)",
            }
          : {
              borderColor: "var(--keyit-protocol-border)",
              color: "var(--keyit-protocol)",
              backgroundColor: "var(--keyit-protocol-soft)",
            }
      }
    >
      <span
        aria-hidden
        className="size-1.5 rounded-full"
        style={{
          backgroundColor: tone === "available" ? "var(--keyit-signal)" : "var(--keyit-protocol)",
        }}
      />
      {label}
      {children ? <span className="font-normal opacity-80">— {children}</span> : null}
    </span>
  );
}

/** Implemented today by the shipped `keyit` CLI / relay. */
export function Available({ children }: { children?: ReactNode }) {
  return (
    <StatusBadge tone="available" label="Available now">
      {children}
    </StatusBadge>
  );
}

/** Frozen in the v1 protocol spec, not yet exposed by the CLI. */
export function ProtocolDefined({ children }: { children?: ReactNode }) {
  return (
    <StatusBadge tone="protocol" label="Protocol-defined">
      {children}
    </StatusBadge>
  );
}
