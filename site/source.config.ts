import { defineConfig, defineDocs } from "fumadocs-mdx/config";

// `docs` is the one content collection for this first pass: the approved
// documentation IA under `content/docs/**`. If the site later grows a
// second MDX-backed collection (e.g. blog/changelog), add it here rather
// than repurposing this one — Fumadocs keys collections by name, and the
// generated `.source` types depend on that name staying stable.
export const docs = defineDocs({
  dir: "content/docs",
});

export default defineConfig({
  mdxOptions: {
    // Defaults (GFM, heading anchors, remark-structure for search, Shiki
    // via rehype-code) are what we want for now. Revisit here if/when the
    // docs need something beyond prose + fenced code blocks (e.g. Mermaid
    // diagrams for the Protocol section).
    //
    // Themes are the one default overridden: `github-light`/`github-dark`
    // (Shiki's own default pair) is the single most recognizable "stock
    // Fumadocs" tell — literally GitHub's own syntax palette. `min-*` is
    // Shiki's most restrained bundled pair (near-monochrome, sparing
    // syntax color), which matches the site's Protocol Schematic /
    // Terminal Ledger direction — see the visual-direction writeup.
    rehypeCodeOptions: {
      themes: {
        light: "min-light",
        dark: "min-dark",
      },
    },
  },
});
