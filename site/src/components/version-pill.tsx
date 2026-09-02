"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { CURRENT_DOC_VERSION, DOC_VERSIONS } from "@/lib/versions";

export function VersionPill({ className }: { className?: string }) {
  if (DOC_VERSIONS.length <= 1) {
    return (
      <Link
        href={CURRENT_DOC_VERSION.href}
        className={`keyit-surface inline-flex items-center gap-1.5 border border-fd-border px-2.5 py-1 font-mono text-[11px] text-fd-muted-foreground transition-colors hover:text-fd-foreground hover:border-fd-foreground/30 ${className ?? ""}`}
      >
        <VersionDot />
        Docs: {CURRENT_DOC_VERSION.label} <span className="opacity-60">·</span>{" "}
        {CURRENT_DOC_VERSION.status}
      </Link>
    );
  }

  return <VersionSelector className={className} />;
}

function VersionDot() {
  return (
    <span
      aria-hidden
      className="size-1.5 rounded-full"
      style={{ backgroundColor: "var(--keyit-signal)" }}
    />
  );
}

function VersionSelector({ className }: { className?: string }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onPointerDown(event: PointerEvent) {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, []);

  return (
    <div ref={rootRef} className={`relative inline-block ${className ?? ""}`}>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="keyit-surface inline-flex items-center gap-1.5 border border-fd-border px-2.5 py-1 font-mono text-[11px] text-fd-muted-foreground transition-colors hover:text-fd-foreground hover:border-fd-foreground/30"
      >
        <VersionDot />
        Docs: {CURRENT_DOC_VERSION.label} <span className="opacity-60">·</span>{" "}
        {CURRENT_DOC_VERSION.status}
      </button>
      {open ? (
        <ul
          role="listbox"
          className="keyit-surface absolute top-[calc(100%+4px)] left-0 z-10 min-w-[10rem] border border-fd-border bg-fd-popover py-1 shadow-sm"
        >
          {DOC_VERSIONS.map((version) => (
            <li key={version.id}>
              <Link
                href={version.href}
                onClick={() => setOpen(false)}
                className="flex items-center justify-between gap-3 px-3 py-1.5 font-mono text-[11px] text-fd-popover-foreground transition-colors hover:bg-fd-accent"
              >
                {version.label}
                <span className="text-fd-muted-foreground">{version.status}</span>
              </Link>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
