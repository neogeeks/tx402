import { docsLoader } from "@astrojs/starlight/loaders";
import { docsSchema } from "@astrojs/starlight/schema";
import { defineCollection } from "astro:content";

/**
 * Registers `src/content/docs/**` as Starlight's `docs` collection.
 *
 * Astro 5 onward will not discover content without this file — it builds a site with one
 * 404 page and warns rather than failing, so its absence looks like an empty site rather
 * than a misconfiguration.
 */
export const collections = {
  docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),
};
