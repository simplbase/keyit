import Link from 'next/link';
import {
  ArrowUpRight,
  BookOpen,
  CheckCircle2,
  CircleDot,
  Code2,
  FileText,
  GitBranch,
  KeyRound,
  Laptop,
  Lock,
  Server,
  Shield,
  Terminal,
} from 'lucide-react';

const commands = [
  ['init', 'keyit init'],
  ['add', 'keyit env add dev .env.local'],
  ['push', 'keyit push --env dev'],
  ['pull', 'keyit pull --env dev'],
];

const heroFacts = [
  ['relay sees', 'ciphertext and metadata'],
  ['cli prints', 'keys, ids, paths'],
  ['trust lives in', 'approved devices'],
];

const ledgerRows = [
  ['rev 014', 'developer-a', 'staging env update', 'ciphertext only'],
  ['rev 013', 'developer-b', 'webhook key rotation', 'ciphertext only'],
  ['rev 012', 'developer-a', 'local flags synced', 'ciphertext only'],
];

const boundaryItems = [
  {
    icon: Lock,
    title: 'Plaintext stays local',
    text: 'Values are sealed before upload. If the relay can read them, the tool has already failed.',
  },
  {
    icon: KeyRound,
    title: 'Trust machines, not vibes',
    text: 'Access is a device decision: invite it, approve it, revoke it when the laptop should stop receiving state.',
  },
  {
    icon: Shield,
    title: 'Refusals are a feature',
    text: 'Pull will not overwrite local changes by accident. Push will not pretend a stale base is fine.',
  },
];

const workflowItems = [
  {
    label: '01',
    title: 'Commit the map',
    text: 'Keep project metadata in Git. Keep environment values out of it.',
  },
  {
    label: '02',
    title: 'Approve the machine',
    text: 'A teammate gets state only after their device joins and an owner approves it.',
  },
  {
    label: '03',
    title: 'Push sealed state',
    text: 'The relay carries revisions. It does not get promoted into your secrets authority.',
  },
  {
    label: '04',
    title: 'Inspect without leaking',
    text: 'Status and diff show drift and key names, not the private values your team is trying to protect.',
  },
];

const docLinks = [
  {
    icon: Terminal,
    title: 'Quickstart',
    text: 'Try the whole loop locally before you trust it with real state.',
    href: '/docs/quickstart',
  },
  {
    icon: GitBranch,
    title: 'Revisions',
    text: 'See how history, summaries, base pointers, and stale pushes actually work.',
    href: '/docs/revisions',
  },
  {
    icon: Server,
    title: 'Relay',
    text: 'Use ours when time is tight. Run your own when policy says so.',
    href: '/docs/relay',
  },
];

export default function HomePage() {
  return (
    <main className="keyit-home">
      <section className="keyit-hero" aria-labelledby="keyit-hero-title">
        <div className="keyit-hero-bg" aria-hidden="true">
          <img src="/keyit-logomark.svg" alt="" />
          <span>keyit</span>
        </div>

        <div className="keyit-hero-shell">
          <div className="keyit-hero-copy">
            <p className="keyit-eyebrow">
              <img src="/keyit-logomark.svg" alt="" />
              Encrypted dotenv sync for teams that know better
            </p>
            <h1 id="keyit-hero-title">Stop pasting secrets like it is normal.</h1>
            <p className="keyit-lede">
              Keyit moves environment files between approved developer machines. Chat is not a vault.
              Git is not a vault. That shared doc is definitely not a vault.
            </p>
            <div className="keyit-actions">
              <Link className="keyit-button keyit-button-primary" href="/docs/quickstart">
                <BookOpen aria-hidden="true" />
                Read the quickstart
                <ArrowUpRight aria-hidden="true" />
              </Link>
              <a className="keyit-button keyit-button-secondary" href="https://github.com/simplbase/keyit">
                <Code2 aria-hidden="true" />
                View source
                <ArrowUpRight aria-hidden="true" />
              </a>
            </div>
          </div>

          <div className="keyit-product-stage">
            <div className="keyit-surface-note" aria-hidden="true">
              <span>local first</span>
              <i />
              <span>relay cannot read</span>
              <i />
              <span>pull intentional</span>
            </div>
            <div className="keyit-product-surface" aria-label="Keyit encrypted revision flow">
            <div className="keyit-surface-header">
              <div>
                <span className="keyit-window-dot" />
                <span className="keyit-window-dot" />
                <span className="keyit-window-dot" />
              </div>
              <strong>keyit workspace</strong>
            </div>

            <div className="keyit-command-grid">
              {commands.map(([label, command]) => (
                <div className="keyit-command-tile" key={command}>
                  <span>{label}</span>
                  <code>$ {command}</code>
                </div>
              ))}
            </div>

            <div className="keyit-flow-rail">
              <div className="keyit-flow-path" aria-hidden="true">
                <span />
                <span />
                <span />
              </div>
              <article>
                <span className="keyit-flow-icon">
                  <Laptop aria-hidden="true" />
                </span>
                <div>
                  <span>local file</span>
                  <strong>.env.local</strong>
                  <small>never committed</small>
                </div>
              </article>
              <article className="keyit-relay-node">
                <span className="keyit-flow-icon">
                  <img src="/keyit-logomark.svg" alt="" />
                </span>
                <div>
                  <span>untrusted relay</span>
                  <strong>rev 014</strong>
                  <small>moves, never reads</small>
                </div>
              </article>
              <article>
                <span className="keyit-flow-icon">
                  <Laptop aria-hidden="true" />
                </span>
                <div>
                  <span>approved device</span>
                  <strong>developer-b</strong>
                  <small>pulls deliberately</small>
                </div>
              </article>
            </div>

            <div className="keyit-revision-panel">
              <div>
                <CircleDot aria-hidden="true" />
                <span>environment</span>
                <strong>dev</strong>
              </div>
              <div>
                <CheckCircle2 aria-hidden="true" />
                <span>status</span>
                <strong>synced</strong>
              </div>
              <div>
                <FileText aria-hidden="true" />
                <span>prints</span>
                <strong>names only</strong>
              </div>
            </div>
            </div>
          </div>
        </div>

        <div className="keyit-hero-strip" aria-label="Keyit protocol guarantees">
          {heroFacts.map(([label, value]) => (
            <div key={label}>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
          </div>
      </section>

      <section className="keyit-statement">
        <p className="keyit-kicker">The line</p>
        <h2>Secrets need a protocol, not a gentleman's agreement.</h2>
        <p>
          Keyit is small on purpose. It is not your cloud secret manager, your developer portal,
          or some enterprise ceremony wearing a CLI costume. It gives project-local private state
          a repeatable path with hard trust boundaries.
        </p>
      </section>

      <section className="keyit-ledger" aria-labelledby="keyit-ledger-title">
        <div className="keyit-ledger-copy">
          <p className="keyit-kicker">Revision ledger</p>
          <h2 id="keyit-ledger-title">The relay is transport. Do not worship it.</h2>
          <p>
            Every push creates a signed environment revision. The relay can store it, order it,
            and serve it back. It still cannot decrypt the useful part.
          </p>
        </div>
        <div className="keyit-ledger-table" aria-label="Example encrypted revision history">
          <div className="keyit-ledger-head">
            <span>revision</span>
            <span>device</span>
            <span>summary</span>
            <span>relay sees</span>
          </div>
          {ledgerRows.map(([revision, device, summary, relay]) => (
            <div className="keyit-ledger-row" key={revision}>
              <strong>{revision}</strong>
              <span>{device}</span>
              <span>{summary}</span>
              <code>{relay}</code>
            </div>
          ))}
          <div className="keyit-ledger-footer">
            <Lock aria-hidden="true" />
            <span>dotenv values decrypt only on approved devices</span>
          </div>
        </div>
      </section>

      <section className="keyit-boundaries" aria-labelledby="keyit-boundaries-title">
        <div className="keyit-section-heading">
          <p className="keyit-kicker">Hard boundaries</p>
          <h2 id="keyit-boundaries-title">A small tool that says no at the right time.</h2>
        </div>
        <div className="keyit-boundary-grid">
          {boundaryItems.map((item) => (
            <article key={item.title}>
              <item.icon aria-hidden="true" />
              <h3>{item.title}</h3>
              <p>{item.text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="keyit-workflow" aria-labelledby="keyit-workflow-title">
        <div className="keyit-section-heading">
          <p className="keyit-kicker">The working loop</p>
          <h2 id="keyit-workflow-title">Four commands instead of a security theatre meeting.</h2>
        </div>
        <div className="keyit-workflow-list">
          {workflowItems.map((item) => (
            <article key={item.label}>
              <span>{item.label}</span>
              <div>
                <h3>{item.title}</h3>
                <p>{item.text}</p>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="keyit-docs-panel" aria-labelledby="keyit-docs-title">
        <div className="keyit-section-heading">
          <p className="keyit-kicker">Documentation map</p>
          <h2 id="keyit-docs-title">Read the part that can hurt you first.</h2>
        </div>
        <div className="keyit-doc-link-grid">
          {docLinks.map((item) => (
            <Link href={item.href} key={item.href}>
              <item.icon aria-hidden="true" />
              <span>{item.title}</span>
              <p>{item.text}</p>
              <ArrowUpRight aria-hidden="true" />
            </Link>
          ))}
        </div>
      </section>

      <section className="keyit-final">
        <div>
          <p className="keyit-kicker">Hosted or self-hosted</p>
          <h2>Use our relay if you need the cheap path. Run your own damn relay if you need control.</h2>
        </div>
        <p>
          The hosted relay is for speed and small teams. Self-hosting is for policy, budget,
          audits, and people who do not want another vendor-shaped dependency. The protocol is
          the same either way.
        </p>
        <div className="keyit-actions">
          <Link className="keyit-button keyit-button-primary" href="/docs/installation">
            Install Keyit
            <ArrowUpRight aria-hidden="true" />
          </Link>
          <a className="keyit-button keyit-button-secondary" href="https://github.com/simplbase/keyit">
            Source
            <ArrowUpRight aria-hidden="true" />
          </a>
        </div>
      </section>

      <footer className="keyit-footer">
        <strong>keyit</strong>
        <span>Private project state without the paste ritual.</span>
        <Link href="/docs">Documentation <ArrowUpRight aria-hidden="true" /></Link>
      </footer>
    </main>
  );
}
