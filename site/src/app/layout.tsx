import { RootProvider } from 'fumadocs-ui/provider/next';
import './global.css';
import type { Metadata } from 'next';

const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? 'https://keyit.sh';

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: 'Keyit | Stop pasting secrets.',
    template: '%s | Keyit',
  },
  description:
    'Encrypted dotenv sync for teams that want approved devices, untrusted relays, and no paste ritual.',
  icons: {
    icon: [
      { url: '/keyit-logomark.svg', type: 'image/svg+xml' },
      { url: '/keyit-logomark.png', type: 'image/png' },
    ],
    apple: [{ url: '/keyit-logomark.png', type: 'image/png' }],
  },
};

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="flex flex-col min-h-screen">
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
