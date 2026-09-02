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
  manifest: "/manifest.webmanifest",
  alternates: {
    canonical: "/",
  },
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "16x16 32x32", type: "image/x-icon" },
      { url: "/keyit-square-cutout.svg", sizes: "1024x1024", type: "image/svg+xml" },
      { url: "/icon-192.png", sizes: "192x192", type: "image/png" },
      { url: "/icon-512.png", sizes: "512x512", type: "image/png" },
    ],
    shortcut: [{ url: "/favicon.ico", type: "image/x-icon" }],
    apple: [{ url: "/apple-icon.png", sizes: "180x180", type: "image/png" }],
  },
  openGraph: {
    type: "website",
    url: SITE_URL,
    siteName: SITE_NAME,
    title: `${SITE_NAME} — private project state, synced securely`,
    description: SITE_DESCRIPTION,
    images: [
      {
        url: "/icon-512.png",
        width: 512,
        height: 512,
        alt: "Keyit mark",
      },
    ],
  },
  twitter: {
    card: "summary",
    title: `${SITE_NAME} — private project state, synced securely`,
    description: SITE_DESCRIPTION,
    images: ["/icon-512.png"],
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
