/**
 * Deterministic local EVM JSON-RPC stub (SPEC §13, "chain simulation").
 *
 * The Base adapter reaches the chain through exactly two calls — `eth_chainId` and an
 * `eth_call` of `balanceOf` — so a faithful harness for it is a small server that answers
 * those two and nothing else. That is deliberate: a stub that answered more would let a
 * regression widen tx402's RPC surface past what SPEC §7.1 permits without a test noticing.
 *
 * Everything it returns is a pure function of its configuration and the request. There is no
 * clock and no randomness, so a failing integration test fails the same way twice.
 *
 * The failure modes exist because SPEC's normative scenarios need them: a wrong chain ID is
 * SPEC §7.1's mismatch rule and SPEC §9.1's RPC-spoofing threat, and hang/error/http drive
 * the failover paths that T-008 and T-020 will exercise at M5.
 *
 * @example
 * ```js
 * const rpc = await createEvmRpcStub({ chainId: 8453, balances: { "0xabc…": "5000000" } });
 * // point a signed test manifest's rpcUrls at rpc.url
 * await rpc.close();
 * ```
 */

import { createServer } from "node:http";
import { once } from "node:events";

/** `balanceOf(address)`. Mirrors the selector the SDK sends; the stub verifies it. */
const BALANCE_OF_SELECTOR = "0x70a08231";

/**
 * @typedef {"ok"|"wrong-chain"|"hang"|"rpc-error"|"http-error"|"garbage"} StubMode
 *
 * - `ok`          answers normally
 * - `wrong-chain` reports `wrongChainId` from `eth_chainId` — SPEC §7.1 mismatch
 * - `hang`        never responds, so the caller's 600 ms deadline fires
 * - `rpc-error`   a well-formed JSON-RPC error envelope
 * - `http-error`  HTTP 503
 * - `garbage`     HTTP 200 with a body that is not JSON
 */

/**
 * @typedef {object} EvmRpcStubOptions
 * @property {number} [chainId]               default 8453 (Base mainnet)
 * @property {number} [wrongChainId]          reported in `wrong-chain` mode; default 1
 * @property {Record<string, string>} [balances]  owner address (any case) to atomic string
 * @property {string} [defaultBalance]        for owners not in `balances`; default "0"
 * @property {string} [token]                 only this token address is served, if set
 * @property {StubMode} [mode]                default "ok"
 * @property {number} [port]                  default 0 (ephemeral)
 */

/**
 * Starts the stub.
 *
 * @param {EvmRpcStubOptions} [options]
 */
export async function createEvmRpcStub(options = {}) {
  const {
    chainId = 8453,
    wrongChainId = 1,
    balances = {},
    defaultBalance = "0",
    token,
    mode: initialMode = "ok",
    port = 0,
  } = options;

  /** @type {StubMode} */
  let mode = initialMode;
  /** @type {{ method: string, params: unknown[] }[]} */
  const calls = [];
  /** Sockets held open by `hang`; closed on shutdown so the process can exit. */
  const hung = new Set();
  const balanceByOwner = new Map(
    Object.entries(balances).map(([owner, value]) => [owner.toLowerCase(), value]),
  );

  /** @param {bigint} value */
  const quantity = (value) => `0x${value.toString(16)}`;

  /** @param {string} data */
  function decodeBalanceOf(data) {
    if (typeof data !== "string" || !data.startsWith(BALANCE_OF_SELECTOR)) return null;
    const argument = data.slice(BALANCE_OF_SELECTOR.length);
    if (argument.length !== 64) return null;
    return `0x${argument.slice(24)}`.toLowerCase();
  }

  const server = createServer((request, response) => {
    void (async () => {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const raw = Buffer.concat(chunks).toString("utf8");

      /** @param {number} status @param {string} body */
      const send = (status, body) => {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(body);
      };

      if (mode === "hang") {
        hung.add(response);
        response.on("close", () => hung.delete(response));
        return;
      }
      if (mode === "http-error") {
        send(503, JSON.stringify({ error: "stub-unavailable" }));
        return;
      }
      if (mode === "garbage") {
        response.writeHead(200, { "content-type": "application/json" });
        response.end("<not json>");
        return;
      }

      let envelope;
      try {
        envelope = JSON.parse(raw);
      } catch {
        send(400, JSON.stringify({ error: "malformed-request" }));
        return;
      }

      const { id = null, method, params = [] } = envelope ?? {};
      calls.push({ method, params });

      /** @param {unknown} result */
      const ok = (result) => send(200, JSON.stringify({ jsonrpc: "2.0", id, result }));
      /** @param {string} message */
      const fail = (message) =>
        send(200, JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32000, message } }));

      if (mode === "rpc-error") {
        fail("stub-configured-error");
        return;
      }

      switch (method) {
        case "eth_chainId":
          ok(quantity(BigInt(mode === "wrong-chain" ? wrongChainId : chainId)));
          return;

        case "eth_call": {
          const [call] = params;
          if (!call || typeof call !== "object") {
            fail("missing call object");
            return;
          }
          if (
            token !== undefined &&
            String(call.to).toLowerCase() !== token.toLowerCase()
          ) {
            fail("unknown token contract");
            return;
          }
          const owner = decodeBalanceOf(call.data);
          if (owner === null) {
            // Anything other than balanceOf is outside the SPEC §7.1 buyer RPC surface.
            fail("only balanceOf(address) is served");
            return;
          }
          ok(
            `0x${BigInt(balanceByOwner.get(owner) ?? defaultBalance)
              .toString(16)
              .padStart(64, "0")}`,
          );
          return;
        }

        default:
          fail(`method ${String(method)} is outside the buyer RPC surface`);
      }
    })();
  });

  server.listen(port, "127.0.0.1");
  await once(server, "listening");

  const address = /** @type {import("node:net").AddressInfo} */ (server.address());
  const url = `http://127.0.0.1:${address.port}`;

  return {
    url,
    port: address.port,
    chainId,
    /** Every JSON-RPC call received, in order. */
    calls,
    get mode() {
      return mode;
    },
    /** @param {StubMode} next */
    setMode(next) {
      mode = next;
    },
    /** @param {string} owner @param {string} atomic */
    setBalance(owner, atomic) {
      balanceByOwner.set(owner.toLowerCase(), atomic);
    },
    reset() {
      calls.length = 0;
    },
    async close() {
      for (const held of hung) held.destroy();
      hung.clear();
      server.closeAllConnections();
      server.close();
      await once(server, "close");
    },
  };
}
