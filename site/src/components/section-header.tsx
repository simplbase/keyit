import type { ReactNode } from "react";

/**
 * Shared section header for the homepage's numbered sections — a small
 * mono eyebrow (numbered, since the homepage is a sequence a reader
 * moves through top to bottom) plus a heading and optional dek. Kept as
 * one component so heading level and spacing can't drift section to
 * section.
 */
export function SectionHeader({
  id,
  index,
  eyebrow,
  title,
  dek,
  className,
}: {
  id: string;
  index: string;
  eyebrow: string;
  title: string;
  dek?: ReactNode;
  className?: string;
}) {
  return (
    <div className={`mb-8 max-w-2xl sm:mb-10 ${className ?? ""}`}>
      <div className="mb-3 flex items-baseline gap-3 font-mono text-xs tracking-wide text-fd-muted-foreground">
        <span aria-hidden>{index}</span>
        <span className="uppercase tracking-[0.08em]">{eyebrow}</span>
      </div>
      <h2 id={id} className="text-balance text-2xl font-semibold tracking-tight text-fd-foreground sm:text-[1.7rem]">
        {title}
      </h2>
      {dek ? <p className="mt-3 text-[15px] leading-relaxed text-fd-muted-foreground">{dek}</p> : null}
    </div>
  );
}
