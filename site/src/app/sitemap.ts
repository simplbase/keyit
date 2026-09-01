import type { MetadataRoute } from "next";

import { source } from "@/lib/source";

// See site/src/app/layout.tsx: keyit.sh is the canonical site domain.
const SITE_URL = "https://keyit.sh";

export default function sitemap(): MetadataRoute.Sitemap {
  const docs = source.getPages().map((page) => ({
    url: `${SITE_URL}${page.url}`,
    changeFrequency: "weekly" as const,
  }));

  return [
    {
      url: SITE_URL,
      changeFrequency: "monthly",
      priority: 1,
    },
    ...docs,
  ];
}
