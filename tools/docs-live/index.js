#!/usr/bin/env node
/**
 * Proves the documentation SPEC §12.4 requires is actually reachable (**O49**).
 *
 *   node tools/docs-live/index.js paths                      # what must be published
 *   node tools/docs-live/index.js check [--base <url>]       # probe a live site
 *   node tools/docs-live/index.js selftest                   # prove the probe can fail
 *
 * **The failure this exists to stop.** SPEC §12.4 lists "API docs, migration notes,
 * examples, and the error reference published" as a release-blocking gate, and on
 * 2026-08-04 the S15 audit found `http://tx402.dev/docs/` redirecting to
 * `http://www.tx402.dev/docs`, which returned 404, while HTTPS timed out. (The site has
 * since moved to `docs.tx402.io`, which is where `DEFAULT_BASE` points; `tx402.dev` was
 * never on Cloudflare and is not the project's domain.) Nothing noticed,
 * because the docs workflow deliberately *succeeded* when its deploy token was absent and
 * the release workflow neither depended on it nor probed the site. A tag could therefore
 * publish both packages while the Documentation URL printed by `tx402 --help` — and
 * embedded in both packages' registry metadata — was dead.
 *
 * **What "reachable" means here, precisely.** A final status of 200 after redirects, an
 * HTML content type, and a body long enough not to be an error page. The audit's failure
 * was a *redirect to a 404*, so following redirects and then insisting on 200 is the check
 * that would have caught it; asserting the pre-redirect status would not have.
 *
 * This is not part of `pnpm check`. A local gate that needs the public internet fails on a
 * plane, and a gate that fails for reasons unrelated to the change gets disabled. It runs
 * where it means something: after a deploy, and before a publish.
 */

import { createServer } from "node:http";

/** The site root. Matches `PROJECT_URLS.documentation` in both packages exactly. */
const DEFAULT_BASE = "https://docs.tx402.io";

/**
 * The pages SPEC §12.4 names, mapped onto this site's routes.
 *
 * Each entry says which clause of §12.4 it satisfies, so a page cannot be dropped from the
 * list without someone answering "then what covers that requirement?".
 */
const REQUIRED = [
  { path: "/", covers: "documentation root — the URL both packages publish" },
  { path: "/start/quickstart", covers: "SPEC §12.4 examples" },
  { path: "/reference/api-typescript", covers: "SPEC §12.4 API docs" },
  { path: "/reference/configuration", covers: "SPEC §12.4 API docs" },
  { path: "/reference/errors", covers: "SPEC §12.4 error reference" },
  { path: "/guides/lifecycle", covers: "SPEC §12.4 migration notes / semantics" },
  { path: "/guides/policy", covers: "SPEC §12.4 API docs" },
  { path: "/security", covers: "SPEC §9 threat model" },
];

/** Anything shorter than this is an error page, not a documentation page. */
const MIN_BODY_BYTES = 512;

/**
 * Probes one URL. Returns `{ ok, detail }` rather than throwing, so one dead page does not
 * hide the state of the other seven — an operator fixing this wants the whole list.
 *
 * @param {string} url
 * @param {number} timeoutMs
 */
async function probe(url, timeoutMs = 15_000) {
  let response;
  try {
    response = await fetch(url, {
      redirect: "follow",
      headers: { "user-agent": "tx402-docs-live" },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    return {
      ok: false,
      detail: `unreachable — ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  if (response.status !== 200) {
    // Reported with the final URL, because the audit's failure was a redirect that landed
    // on a 404 and "302" alone would have looked like a working site.
    return { ok: false, detail: `HTTP ${response.status} at ${response.url}` };
  }
  const type = response.headers.get("content-type") ?? "";
  if (!type.includes("text/html")) {
    return { ok: false, detail: `content-type ${type || "(absent)"} at ${response.url}` };
  }
  const body = await response.text();
  if (body.length < MIN_BODY_BYTES) {
    return { ok: false, detail: `body is ${body.length} bytes — too short to be a page` };
  }
  return { ok: true, detail: `200, ${body.length} bytes` };
}

/** @param {string} base */
async function check(base) {
  const root = base.replace(/\/+$/u, "");
  console.log(`tx402-docs-live: probing ${root}\n`);
  let failed = 0;
  for (const entry of REQUIRED) {
    const url = `${root}${entry.path}`;
    // Sequential on purpose: eight parallel requests to a site that is down produces eight
    // identical timeouts and no more information than one.
    const result = await probe(url);
    if (!result.ok) failed += 1;
    console.log(
      `  ${result.ok ? "OK  " : "FAIL"}  ${entry.path.padEnd(34)} ${result.detail}`,
    );
    if (!result.ok) console.log(`        covers: ${entry.covers}`);
  }
  if (failed > 0) {
    console.error(
      `\ntx402-docs-live: ${failed} of ${REQUIRED.length} required pages are not published.` +
        "\nSPEC §12.4 makes published documentation a release-blocking gate.",
    );
    process.exitCode = 1;
    return;
  }
  console.log(`\nOK    all ${REQUIRED.length} required pages are published and reachable`);
}

/**
 * Proves the probe can fail, against a local server that is wrong in each realistic way.
 *
 * Without this the gate would only ever have been observed passing, which is precisely the
 * state O48 and O49 found the release checks in.
 */
async function selftest() {
  const page = `<!doctype html><html><body>${"x".repeat(MIN_BODY_BYTES)}</body></html>`;
  const server = createServer((request, response) => {
    const url = request.url ?? "/";
    if (url.startsWith("/good")) {
      response.writeHead(200, { "content-type": "text/html" }).end(page);
    } else if (url.startsWith("/redirect-to-404")) {
      response.writeHead(302, { location: "/missing" }).end();
    } else if (url.startsWith("/missing")) {
      response.writeHead(404, { "content-type": "text/html" }).end("not found");
    } else if (url.startsWith("/json")) {
      response.writeHead(200, { "content-type": "application/json" }).end("{}");
    } else if (url.startsWith("/stub")) {
      response.writeHead(200, { "content-type": "text/html" }).end("<html></html>");
    } else {
      response.writeHead(500).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = /** @type {import("node:net").AddressInfo} */ (server.address());
  const base = `http://127.0.0.1:${port}`;

  const cases = [
    { path: "/good", expect: true, label: "a real page" },
    { path: "/redirect-to-404", expect: false, label: "a redirect that lands on a 404" },
    { path: "/missing", expect: false, label: "a plain 404" },
    { path: "/json", expect: false, label: "a 200 that is not HTML" },
    { path: "/stub", expect: false, label: "a 200 whose body is a stub" },
    { path: "/boom", expect: false, label: "a 500" },
  ];

  let failed = 0;
  for (const item of cases) {
    const result = await probe(`${base}${item.path}`, 3_000);
    const correct = result.ok === item.expect;
    if (!correct) failed += 1;
    console.log(
      `  ${correct ? "OK  " : "FAIL"}  ${item.expect ? "accepts" : "rejects"}: ${item.label} (${result.detail})`,
    );
  }
  // An unreachable origin, with nothing listening at all.
  server.close();
  const dead = await probe(`${base}/good`, 2_000);
  const deadCorrect = dead.ok === false;
  if (!deadCorrect) failed += 1;
  console.log(
    `  ${deadCorrect ? "OK  " : "FAIL"}  rejects: an origin that is not listening (${dead.detail})`,
  );

  if (failed > 0) {
    console.error(`\ntx402-docs-live: ${failed} self-test case(s) behaved incorrectly`);
    process.exitCode = 1;
    return;
  }
  console.log(`\nOK    ${cases.length + 1} negative fixtures behave as specified`);
}

const [command = "check", ...rest] = process.argv.slice(2);
const baseIndex = rest.indexOf("--base");
const base =
  baseIndex === -1 ? (process.env.TX402_DOCS_BASE ?? DEFAULT_BASE) : rest[baseIndex + 1];

if (command === "paths") {
  for (const entry of REQUIRED) console.log(`${entry.path}\t${entry.covers}`);
} else if (command === "check") {
  await check(base ?? DEFAULT_BASE);
} else if (command === "selftest") {
  await selftest();
} else {
  console.error(`tx402-docs-live: unknown command ${JSON.stringify(command)}`);
  console.error("usage: docs-live <paths|check|selftest> [--base <url>]");
  process.exitCode = 2;
}
