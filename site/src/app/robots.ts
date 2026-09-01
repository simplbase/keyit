import type { MetadataRoute } from "next";

// See site/src/app/layout.tsx: keyit.sh is the canonical site domain.
const SITE_URL = "https://keyit.sh";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: "/",
    },
    sitemap: `${SITE_URL}/sitemap.xml`,
  };
}
