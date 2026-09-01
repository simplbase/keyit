"use client";

import { useState, type CSSProperties } from "react";

export type TerminalLine =
  | { type: "command"; text: string }
  | { type: "output"; text: string; tone?: "default" | "success" | "muted" }
  | { type: "blank" };

/**
 * A restrained, reusable terminal panel — the site's core recurring UI
 * element. It renders a real command/output transcript, not a fake
 * dashboard: no window controls that do anything, no chrome beyond a
 * thin label bar, no glow.
 *
 * Every `command` line's text is copyable independently (real terminal
 * behavior — you copy one command, not a whole scrollback). Reveal
 * animation is a short, per-line stagger; `prefers-reduced-motion`
 * disables it entirely via CSS, and the transcript is fully present and
 * readable either way — motion never carries information on its own.
 *
 * All command syntax rendered through this component must be verified
 * against `keyit-cli/src/main.rs` before use.
 */
export function Terminal({
  lines,
  label = "shell",
  className,
}: {
  lines: TerminalLine[];
  label?: string;
  className?: string;
}) {
  return (
    <div
      className={`keyit-surface overflow-hidden border border-fd-border bg-fd-card ${className ?? ""}`}
      role="group"
      aria-label={`Terminal transcript: ${label}`}
    >
      <div className="flex items-center gap-2 border-b border-fd-border bg-fd-muted/60 px-3.5 py-2">
        <span aria-hidden className="flex gap-1.5">
          <span className="size-2 rounded-full bg-fd-muted-foreground/25" />
          <span className="size-2 rounded-full bg-fd-muted-foreground/25" />
          <span className="size-2 rounded-full bg-fd-muted-foreground/25" />
        </span>
        <span className="font-mono text-[11px] tracking-tight text-fd-muted-foreground">
          {label}
        </span>
      </div>
      <div className="overflow-x-auto px-4 py-3.5 font-mono text-[13px] leading-[1.85] sm:text-[13.5px]">
        {lines.map((line, i) => (
          <TerminalRow key={i} line={line} index={i} />
        ))}
      </div>
    </div>
  );
}

function TerminalRow({ line, index }: { line: TerminalLine; index: number }) {
  const [copied, setCopied] = useState(false);

  if (line.type === "blank") {
    return <div aria-hidden className="h-[0.85em]" />;
  }

  const style = { animationDelay: `${Math.min(index, 10) * 45}ms` } as CSSProperties;

  if (line.type === "command") {
    const copy = async () => {
      try {
        await navigator.clipboard.writeText(line.text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1400);
      } catch {
        /* clipboard unavailable — no-op, the text is still selectable */
      }
    };
    return (
      <div className="keyit-line group flex items-start gap-2 whitespace-pre-wrap break-words" style={style}>
        <span aria-hidden className="select-none text-fd-primary">
          $
        </span>
        <code className="flex-1 text-fd-foreground">{line.text}</code>
        <button
          type="button"
          onClick={copy}
          className="mt-[-1px] shrink-0 rounded-sm px-1.5 py-0.5 text-[10px] tracking-wide text-fd-muted-foreground opacity-0 transition-opacity hover:text-fd-foreground focus-visible:opacity-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-fd-ring group-hover:opacity-100"
          aria-label={`Copy command: ${line.text}`}
        >
          {copied ? "copied" : "copy"}
        </button>
      </div>
    );
  }

  const tone =
    line.tone === "success"
      ? "text-fd-primary"
      : line.tone === "muted"
        ? "text-fd-muted-foreground"
        : "text-fd-muted-foreground";

  return (
    <div
      className={`keyit-line whitespace-pre-wrap break-words pl-[1.15em] ${tone}`}
      style={style}
    >
      {line.text}
    </div>
  );
}
