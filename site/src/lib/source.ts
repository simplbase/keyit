import { docs } from "@/.source";
import { loader } from "fumadocs-core/source";

// The single content source for `/docs/**`, built from the MDX collection
// declared in `source.config.ts`. `docs.toFumadocsSource()` is generated
// by the Fumadocs MDX build step (`.source/`) from `content/docs/**` and
// its `meta.json` files — the page tree here is derived from those files,
// not hand-maintained.
export const source = loader({
  baseUrl: "/docs",
  source: docs.toFumadocsSource(),
});
