import Link from "next/link";
import type { ReactNode } from "react";

export interface ResourceLink {
  label: string;
  href: string;
  external?: boolean;
}

export interface ResourceGroup {
  title: string;
  links: ResourceLink[];
}

export function ResourceHub({ groups }: { groups: ResourceGroup[] }) {
  return (
    <div className="grid grid-cols-2 gap-x-8 gap-y-10 sm:grid-cols-3 lg:grid-cols-5 lg:gap-x-6">
      {groups.map((group) => (
        <div key={group.title}>
          <h3 className="mb-3 font-mono text-xs uppercase tracking-[0.08em] text-fd-muted-foreground">
            {group.title}
          </h3>
          <ul className="flex flex-col gap-2.5">
            {group.links.map((link) => (
              <li key={link.href}>
                <ResourceLinkItem {...link} />
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

function ResourceLinkItem({ label, href, external }: ResourceLink): ReactNode {
  const className =
    "group inline-flex items-baseline gap-1 text-[13.5px] text-fd-foreground/85 transition-colors hover:text-fd-primary";
  const content = (
    <>
      <span className="border-b border-transparent group-hover:border-current">{label}</span>
      {external ? (
        <span aria-hidden className="text-[10px] text-fd-muted-foreground">
          ↗
        </span>
      ) : null}
    </>
  );

  if (external) {
    return (
      <a href={href} target="_blank" rel="noreferrer" className={className}>
        {content}
      </a>
    );
  }

  return (
    <Link href={href} className={className}>
      {content}
    </Link>
  );
}
