import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";

import { Wordmark } from "@/components/mark";

export const GITHUB_URL = "https://github.com/simplbase/keyit";

export const PROTOCOL_SPEC_URL = `${GITHUB_URL}/blob/main/docs/protocol/keyit-protocol-v1.md`;
export const ARCHITECTURE_URL = `${GITHUB_URL}/blob/main/docs/architecture.md`;
export const TRY_LOCAL_URL = `${GITHUB_URL}/blob/main/docs/try-local.md`;
export const RELAY_DEPLOYMENT_URL = `${GITHUB_URL}/blob/main/docs/relay-container-deployment.md`;
export const RELAY_PRODUCTION_URL = `${GITHUB_URL}/blob/main/docs/relay-production.md`;
export const DOCKER_IMAGE_URL = `${RELAY_DEPLOYMENT_URL}#github-container-registry`;
export const CONTRIBUTING_URL = `${GITHUB_URL}/blob/main/CONTRIBUTING.md`;
export const LICENSE_URL = `${GITHUB_URL}/blob/main/LICENSE`;
export const SECURITY_POLICY_URL = `${GITHUB_URL}/blob/main/SECURITY.md`;

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
