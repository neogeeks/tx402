/**
 * Post-build: emit a Markdown mirror of every docs page and link to it.
 *
 * For each `src/content/docs/**​/*.{md,mdx}` this writes a clean `.md` file into `dist`
 * at the page's own path (e.g. `/guides/policy.md`) and injects
 * `<link rel="alternate" type="text/markdown" href="…">` into that page's built HTML.
 *
 * The point is machine readability: an agent can fetch the raw Markdown of any page instead
 * of parsing rendered HTML. MDX frontmatter, `import` lines, and bare component tags are
 * stripped so the mirror is plain Markdown; prose, lists, and code fences are kept verbatim.
 *
 * Runs as `postbuild` (see package.json), so `astro build` produces `dist` first.
 */
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const docsRoot = path.resolve(here, "..");
const contentDir = path.join(docsRoot, "src/content/docs");
const distDir = path.join(docsRoot, "dist");

/** Recursively list files under a directory. */
function walk(dir) {
  /** @type {string[]} */
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

/** Turn an MDX/MD source into plain Markdown (frontmatter title becomes the H1). */
function toMarkdown(source) {
  let body = source;
  let title = "";
  const fm = body.match(/^---\n([\s\S]*?)\n---\n?/);
  if (fm) {
    const t = fm[1].match(/^title:\s*(.+)$/m);
    if (t) title = t[1].trim().replace(/^["']|["']$/g, "");
    body = body.slice(fm[0].length);
  }
  const lines = body.split("\n");
  const kept = [];
  let inFence = false;
  for (const line of lines) {
    if (/^\s*```/.test(line)) inFence = !inFence;
    if (!inFence) {
      // Drop MDX import/export lines.
      if (/^\s*(import|export)\s.+\bfrom\b.+;?\s*$/.test(line)) continue;
      // Drop lines that are only a JSX component open/close/self-close tag (capitalized).
      if (/^\s*<\/?[A-Z][A-Za-z0-9]*(\s[^>]*)?\/?>\s*$/.test(line)) continue;
    }
    kept.push(line);
  }
  const md = kept
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  return (title ? `# ${title}\n\n` : "") + md + "\n";
}

/** src-relative path (e.g. "guides/cli.mdx") -> route slug ("guides/cli", "" for root). */
function toSlug(rel) {
  const base = rel
    .replace(/\.(md|mdx)$/i, "")
    .split(path.sep)
    .join("/");
  if (base === "index") return "";
  if (base.endsWith("/index")) return base.slice(0, -"/index".length);
  return base;
}

let mirrors = 0;
let links = 0;

for (const file of walk(contentDir)) {
  if (!/\.(md|mdx)$/i.test(file)) continue;
  const rel = path.relative(contentDir, file);
  const slug = toSlug(rel);

  const mdRel = slug === "" ? "index.md" : `${slug}.md`;
  const mdHref = "/" + mdRel;
  const mdOut = path.join(distDir, mdRel);
  mkdirSync(path.dirname(mdOut), { recursive: true });
  writeFileSync(mdOut, toMarkdown(readFileSync(file, "utf8")));
  mirrors += 1;

  const htmlOut =
    slug === "" ? path.join(distDir, "index.html") : path.join(distDir, slug, "index.html");
  if (existsSync(htmlOut)) {
    let html = readFileSync(htmlOut, "utf8");
    if (!html.includes('type="text/markdown"')) {
      const tag = `<link rel="alternate" type="text/markdown" href="${mdHref}" title="Markdown">`;
      html = html.replace("</head>", `${tag}</head>`);
      writeFileSync(htmlOut, html);
      links += 1;
    }
  }
}

console.log(
  `md-mirror: wrote ${mirrors} Markdown mirrors, injected ${links} alternate links`,
);
