import { DocsLayout } from "fumadocs-ui/layouts/docs";

import { VersionPill } from "@/components/version-pill";
import { baseOptions } from "@/lib/layout.shared";
import { source } from "@/lib/source";

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <DocsLayout
      tree={source.pageTree}
      {...baseOptions()}
      sidebar={{ banner: <VersionPill className="w-fit" /> }}
    >
      {children}
    </DocsLayout>
  );
}
