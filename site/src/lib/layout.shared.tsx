import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";

import { Wordmark } from "@/components/mark";

export const GITHUB_URL = "https://github.com/simplbase/keyit";
export const PROTOCOL_SPEC_URL = `${GITHUB_URL}/blob/main/docs/protocol/keyit-protocol-v1.md`;
export const CONTRIBUTING_URL = `${GITHUB_URL}/blob/main/CONTRIBUTING.md`;

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: <Wordmark />,
    },
    links: [
      {
        text: "Docs",
        url: "/docs",
      },
      {
        text: "Security",
        url: "/docs/security",
      },
      {
        text: "Protocol",
        url: PROTOCOL_SPEC_URL,
      },
    ],
    githubUrl: GITHUB_URL,
  };
}
