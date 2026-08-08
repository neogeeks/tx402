/**
 * Cloudflare Pages advanced-mode worker for the tx402 docs.
 *
 * Static assets are served by `env.ASSETS`; this only adds machine-readability on top:
 *   1. Content negotiation — a page requested with `Accept: text/markdown` returns that
 *      page's Markdown mirror as `text/markdown`.
 *   2. `.md` mirrors are served as `text/markdown` with a `Link: …; rel="canonical"` header.
 *   3. HTML pages carry a `Link: …; rel="alternate"; type="text/markdown"` header.
 *
 * It always falls back to `env.ASSETS.fetch(request)`, so any bug degrades to plain static
 * serving rather than breaking the site. `_headers`/`_redirects` are inert in advanced mode,
 * so the sitemap alias is unnecessary — `sitemap.xml` is a real generated file.
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    const accept = request.headers.get("accept") || "";
    const looksLikePage = p.endsWith("/") || !/\.[a-z0-9]+$/i.test(p);

    const pageToMd = (pagePath) => {
      const s = pagePath.replace(/\/$/, "");
      return s === "" ? "/index.md" : `${s}.md`;
    };
    const mdToCanonical = (mdPath) => {
      const base = mdPath.replace(/\.md$/, "").replace(/\/index$/, "");
      return base === "" ? "/" : `${base}/`;
    };

    // 1. Content negotiation.
    if (looksLikePage && !p.endsWith(".md") && accept.includes("text/markdown")) {
      const md = await env.ASSETS.fetch(new Request(new URL(pageToMd(p), url.origin)));
      if (md.ok) {
        const h = new Headers(md.headers);
        h.set("content-type", "text/markdown; charset=utf-8");
        h.set("link", `<${p}>; rel="canonical"`);
        h.set("vary", "Accept");
        return new Response(md.body, { status: 200, headers: h });
      }
    }

    const res = await env.ASSETS.fetch(request);

    // 2. Markdown mirror responses.
    if (p.endsWith(".md")) {
      const h = new Headers(res.headers);
      h.set("content-type", "text/markdown; charset=utf-8");
      h.set("link", `<${mdToCanonical(p)}>; rel="canonical"`);
      return new Response(res.body, { status: res.status, headers: h });
    }

    // 3. Alternate link on HTML pages.
    if ((res.headers.get("content-type") || "").includes("text/html")) {
      const h = new Headers(res.headers);
      h.append("link", `<${pageToMd(p)}>; rel="alternate"; type="text/markdown"`);
      h.set("vary", "Accept");
      return new Response(res.body, { status: res.status, headers: h });
    }

    return res;
  },
};
