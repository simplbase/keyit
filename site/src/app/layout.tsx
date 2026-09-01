import "./globals.css";

import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import type { Metadata } from "next";
import { RootProvider } from "fumadocs-ui/provider/next";

const SITE_URL = "https://keyit.sh";
const SITE_NAME = "Keyit";
const SITE_DESCRIPTION =
  "Keyit is an open-source, local-first protocol and CLI for securely synchronizing private project state — .env files and other environment secrets — across authorized developers and machines, without trusting the relay with plaintext.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: `${SITE_NAME} — private project state, synced securely`,
    template: `%s · ${SITE_NAME}`,
  },
  description: SITE_DESCRIPTION,
  applicationName: SITE_NAME,
  keywords: [
    "keyit",
    "open-source secrets synchronization",
    "dotenv synchronization",
    "environment synchronization",
    "developer secrets",
    "encrypted project state",
    "local-first developer tools",
  ],
  authors: [{ name: "Keyit" }],
  alternates: {
    canonical: "/",
  },
  openGraph: {
    type: "website",
    url: SITE_URL,
    siteName: SITE_NAME,
    title: `${SITE_NAME} — private project state, synced securely`,
    description: SITE_DESCRIPTION,
  },
  twitter: {
    card: "summary_large_image",
    title: `${SITE_NAME} — private project state, synced securely`,
    description: SITE_DESCRIPTION,
  },
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${GeistSans.variable} ${GeistMono.variable}`}
      suppressHydrationWarning
    >
      <body className="flex min-h-screen flex-col antialiased">
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
