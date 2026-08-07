/**
 * Request deadlines (SPEC §4.3, §6.7).
 *
 * These exist because of a defect that reached `main`. Both SDK deadlines — the optional
 * `timeouts.initialRequestMs` and the paid retry's `timeouts.paymentRetryMs` — were built as
 * `AbortSignal.any([callerSignal, AbortSignal.timeout(ms)])`, which reads as the obvious way
 * to layer an SDK deadline over a caller's own signal. It is not: `AbortSignal.timeout` unrefs
 * its timer and the composite holds its sources weakly, so nothing strongly references the
 * timeout signal once the helper returns. Collect it before it fires and the deadline silently
 * never fires at all.
 *
 * The consequence is not a slow request. A paid retry to a merchant that accepts the
 * connection and never answers would hang indefinitely, so the caller never receives the
 * `AmbiguousPaymentError` that SPEC §6.7 requires — the outcome where the money may already
 * have moved is exactly the one that must not be silent. It surfaced as roughly one CI run in
 * six before the cause was understood.
 *
 * **These tests do not force garbage collection, and that is deliberate.** Driving
 * `global.gc()` on an interval inside a vitest worker starves undici badly enough that even a
 * caller's own `AbortController` stops taking effect — the instrument breaks the thing it
 * measures, so a "proof" built on it would prove nothing. The weak-reference behaviour was
 * instead measured in a standalone Node process against a hanging server: the composed signal
 * missed its deadline 10 times out of 10, the explicitly-held one 0 out of 10. What is
 * asserted here is the behaviour that must hold either way — the deadline fires, and layering
 * it never lengthens the caller's own.
 */

import { createServer, type Server, type ServerResponse } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createTx402Client } from "../src/core/client.js";

describe("request deadlines", () => {
  let server: Server;
  let url: string;
  let held: Set<ServerResponse>;

  beforeEach(async () => {
    held = new Set();
    // Accepts the connection and never answers — the shape a deadline exists for.
    server = createServer((_request, response) => {
      held.add(response);
      response.on("close", () => held.delete(response));
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/resource`;
  });

  afterEach(async () => {
    for (const response of held) response.destroy();
    server.closeAllConnections();
    server.close();
    await once(server, "close");
  });

  it("ends a hanging request at the configured deadline", async () => {
    const client = createTx402Client({
      allowInsecureLocalhost: true,
      timeouts: { initialRequestMs: 400 },
    });

    const started = Date.now();
    await expect(client.fetch(url)).rejects.toMatchObject({
      code: "TX402_TRANSPORT",
      details: { causeCategory: "network" },
    });

    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(300);
    // The failure this guards against is unbounded, so the ceiling is what matters.
    expect(elapsed).toBeLessThan(5_000);
  }, 15_000);

  it("honours a caller's own abort with an SDK deadline layered on", async () => {
    const client = createTx402Client({
      allowInsecureLocalhost: true,
      // Long enough that the caller's signal, not this, must be what ends the request.
      timeouts: { initialRequestMs: 30_000 },
    });
    const caller = new AbortController();
    setTimeout(() => caller.abort(new Error("caller changed its mind")), 150);

    const started = Date.now();
    await expect(client.fetch(url, { signal: caller.signal })).rejects.toMatchObject({
      code: "TX402_TRANSPORT",
    });
    // SPEC §4.3: layering a deadline may not lengthen the caller's own.
    expect(Date.now() - started).toBeLessThan(5_000);
  }, 15_000);

  it("leaves the caller's timeout alone when none is configured", async () => {
    const client = createTx402Client({ allowInsecureLocalhost: true });
    const caller = AbortSignal.timeout(200);

    const started = Date.now();
    await expect(client.fetch(url, { signal: caller })).rejects.toMatchObject({
      code: "TX402_TRANSPORT",
    });
    // With no SDK deadline the caller's signal is passed through untouched.
    expect(Date.now() - started).toBeLessThan(5_000);
  }, 15_000);
});
