/**
 * Post-build AI-readiness generator for the tx402 docs.
 *
 * After `astro build` this emits, for machine consumers:
 *   - a Markdown mirror of every page, with YAML frontmatter and a trailing docs-map
 *     section, at BOTH `/<slug>.md` and `/<slug>/index.md` (covers either URL convention);
 *   - `<link rel="alternate" type="text/markdown">` injected into each page's HTML head;
 *   - `sitemap.xml` with `<lastmod>` per page (git commit date of the source);
 *   - `sitemap.md` — a human/agent-readable index grouped by section;
 *   - `llms-full.txt` — the full text of every page concatenated for LLM context.
 *
 * Content negotiation, Link headers, and `.md` Content-Type are handled at request time by
 * `public/_worker.js` (Cloudflare Pages advanced mode). Runs as `postbuild` (see package.json).
 */
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from "node:fs";
import { execSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const docsRoot = path.resolve(here, "..");
const contentDir = path.join(docsRoot, "src/content/docs");
const distDir = path.join(docsRoot, "dist");
const SITE = "https://docs.tx402.io";

/** Top-level directory -> section label (order is the display order). */
const SECTIONS = [
  ["", "Overview"],
  ["start", "Start here"],
  ["guides", "Guides"],
  ["reference", "Reference"],
  ["security", "Security"],
  ["operations", "Operations"],
];
const sectionLabel = (slug) =>
  (SECTIONS.find(([dir]) => dir === slug.split("/")[0]) || [, "Docs"])[1];

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

function parseFrontmatter(src) {
  let title = "";
  let description = "";
  let body = src;
  const m = src.match(/^---\n([\s\S]*?)\n---\n?/);
  if (m) {
    const t = m[1].match(/^title:\s*(.+)$/m);
    if (t) title = t[1].trim().replace(/^["']|["']$/g, "");
    const d = m[1].match(/^description:\s*(.+)$/m);
    if (d) description = d[1].trim().replace(/^["']|["']$/g, "");
    body = src.slice(m[0].length);
  }
  return { title, description, body };
}

/** Strip MDX imports and bare component tags; keep prose, lists, and code fences verbatim. */
function cleanBody(body) {
  const kept = [];
  let inFence = false;
  for (const line of body.split("\n")) {
    if (/^\s*```/.test(line)) inFence = !inFence;
    if (!inFence) {
      if (/^\s*(import|export)\s.+\bfrom\b.+;?\s*$/.test(line)) continue;
      if (/^\s*<\/?[A-Z][A-Za-z0-9]*(\s[^>]*)?\/?>\s*$/.test(line)) continue;
    }
    kept.push(line);
  }
  return kept
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function slugOf(rel) {
  const base = rel
    .replace(/\.(md|mdx)$/i, "")
    .split(path.sep)
    .join("/");
  if (base === "index") return "";
  if (base.endsWith("/index")) return base.slice(0, -"/index".length);
  return base;
}

function gitDate(file) {
  try {
    const out = execSync(`git log -1 --format=%cI -- "${file}"`, {
      cwd: docsRoot,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
    return out || null;
  } catch {
    return null;
  }
}

const today = new Date().toISOString().slice(0, 10);

const pages = [];
for (const file of walk(contentDir)) {
  if (!/\.(md|mdx)$/i.test(file)) continue;
  const rel = path.relative(contentDir, file);
  const slug = slugOf(rel);
  const { title, description, body } = parseFrontmatter(readFileSync(file, "utf8"));
  pages.push({
    slug,
    title,
    description,
    clean: cleanBody(body),
    url: slug === "" ? `${SITE}/` : `${SITE}/${slug}/`,
    mdRel: slug === "" ? "index.md" : `${slug}.md`,
    mdUrl: slug === "" ? `${SITE}/index.md` : `${SITE}/${slug}.md`,
    lastmod: (gitDate(file) || today).slice(0, 10),
    section: sectionLabel(slug),
  });
}

// Order pages by section, then title.
const order = SECTIONS.map(([, label]) => label).concat("Docs");
pages.sort(
  (a, b) =>
    order.indexOf(a.section) - order.indexOf(b.section) || a.title.localeCompare(b.title),
);

let mirrors = 0;
let links = 0;
for (const p of pages) {
  const fm =
    `---\ntitle: ${JSON.stringify(p.title)}\n` +
    `description: ${JSON.stringify(p.description)}\n` +
    `source: ${p.url}\n---\n\n`;
  const mapSection =
    `\n\n## More documentation\n\n` +
    `- Documentation index (Markdown): ${SITE}/sitemap.md\n` +
    `- Machine index: ${SITE}/llms.txt · full text: ${SITE}/llms-full.txt\n` +
    `- This page: ${p.url}\n`;
  const md = fm + (p.title ? `# ${p.title}\n\n` : "") + p.clean + mapSection + "\n";

  const primary = path.join(distDir, p.mdRel);
  mkdirSync(path.dirname(primary), { recursive: true });
  writeFileSync(primary, md);
  mirrors += 1;
  if (p.slug !== "") {
    const alt = path.join(distDir, p.slug, "index.md");
    mkdirSync(path.dirname(alt), { recursive: true });
    writeFileSync(alt, md);
    mirrors += 1;
  }

  const htmlOut =
    p.slug === ""
      ? path.join(distDir, "index.html")
      : path.join(distDir, p.slug, "index.html");
  if (existsSync(htmlOut)) {
    let html = readFileSync(htmlOut, "utf8");
    let changed = false;
    if (!html.includes('type="text/markdown"')) {
      const tag = `<link rel="alternate" type="text/markdown" href="/${p.mdRel}" title="Markdown">`;
      html = html.replace("</head>", `${tag}</head>`);
      links += 1;
      changed = true;
    }
    // Expressive Code renders `<pre data-language="ts"><code>`; also stamp the conventional
    // `class="language-ts"` onto the inner <code> so code-block scanners recognize the language.
    const withClasses = html.replace(
      /<pre\b([^>]*\bdata-language="([^"]+)"[^>]*)>(\s*)<code\b(?![^>]*\bclass="language-)/g,
      (_m, preAttrs, lang, ws) => `<pre${preAttrs}>${ws}<code class="language-${lang}"`,
    );
    if (withClasses !== html) {
      html = withClasses;
      changed = true;
    }
    if (changed) writeFileSync(htmlOut, html);
  }
}

// sitemap.xml with lastmod.
const urlset = pages
  .map(
    (p) =>
      `  <url>\n    <loc>${p.url}</loc>\n    <lastmod>${p.lastmod}</lastmod>\n  </url>`,
  )
  .join("\n");
writeFileSync(
  path.join(distDir, "sitemap.xml"),
  `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urlset}\n</urlset>\n`,
);

// sitemap.md grouped by section.
let smd = `# tx402 documentation — sitemap\n\n> A structured index of the tx402 documentation. Every page also has a Markdown mirror (append \`.md\` to its path).\n\n`;
for (const label of order) {
  const inSec = pages.filter((p) => p.section === label);
  if (!inSec.length) continue;
  smd += `## ${label}\n\n`;
  for (const p of inSec)
    smd += `- [${p.title}](${p.url}) — [markdown](${p.mdUrl})${p.description ? `: ${p.description}` : ""}\n`;
  smd += "\n";
}
writeFileSync(path.join(distDir, "sitemap.md"), smd);

// llms-full.txt: full concatenated text.
let full = `# tx402 — full documentation\n\n> The complete text of the tx402 documentation, concatenated for LLM context. Canonical site: ${SITE}\n`;
for (const label of order) {
  const inSec = pages.filter((p) => p.section === label);
  for (const p of inSec)
    full += `\n\n---\n\n# ${p.title}\n\nSource: ${p.url}\n\n${p.clean}\n`;
}
writeFileSync(path.join(distDir, "llms-full.txt"), full);

console.log(
  `postbuild: ${pages.length} pages -> ${mirrors} md mirrors, ${links} alternate links, sitemap.xml (+lastmod), sitemap.md, llms-full.txt`,
);
