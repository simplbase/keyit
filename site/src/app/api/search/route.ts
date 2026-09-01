import { createFromSource } from "fumadocs-core/search/server";

import { source } from "@/lib/source";

// Orama-backed search: the index is built from `source` at request/build
// time and served from this route — no external search service, no API
// key, nothing to self-host separately from the site itself.
export const { GET } = createFromSource(source);
