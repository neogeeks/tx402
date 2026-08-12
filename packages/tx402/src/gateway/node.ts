/**
 * The reference Node capability gateway (SPEC §12.5) — a small `http.Server` that bridges Node's
 * request/response to the isomorphic {@link handleGatewayRequest} core. It is store-agnostic: an
 * operator fronts Redis by constructing a `RedisSpendStore` data/admin pair (from `tx402/redis`)
 * and passing a {@link GatewayBackend}; the Worker gateway (`tx402/gateway/worker`) is the natural
 * choice for a DO. The gateway holds the raw backend credential server-side and exposes only the
 * §12.5 method set behind a bearer token (SPEC §9.1).
 *
 * @example
 * ```ts
 * import { Redis } from "ioredis";
 * import { RedisSpendStore } from "tx402/redis";
 * import { createGatewayServer, bearerTokenScope } from "tx402/gateway";
 *
 * const client = new Redis(process.env.REDIS_URL!);
 * const backend = {
 *   dataStore: new RedisSpendStore({ client, admin: false }),
 *   adminStore: new RedisSpendStore({ client, admin: true }),
 *   resolveScope: bearerTokenScope({
 *     dataToken: process.env.TX402_GATEWAY_DATA_TOKEN!,
 *     adminToken: process.env.TX402_GATEWAY_ADMIN_TOKEN!,
 *   }),
 * };
 * createGatewayServer(backend).listen(8787);
 * ```
 */

import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";

import {
  GATEWAY_MAX_REQUEST_BODY_BYTES,
  handleGatewayRequest,
  type GatewayBackend,
} from "./gateway.js";
import { gatewayConditionBody } from "./wire.js";

/**
 * The largest request body the Node gateway will buffer. Every §12.5 request body is a small
 * named-field JSON object (the biggest, `reserve`, is well under 1 KiB), so 64 KiB is generous. A
 * body that would exceed it — or an unauthenticated caller — is refused BEFORE the whole stream is
 * read, so a remote caller cannot force unbounded memory use without a credential (O25). Shared
 * with the isomorphic core so the Node and Worker gateways enforce the SAME ceiling (O51).
 */
const MAX_REQUEST_BODY_BYTES = GATEWAY_MAX_REQUEST_BODY_BYTES;

/**
 * How much of a rejected request body the gateway will read-and-discard (never buffer) before it
 * gives up and hard-resets the socket. A refusal that just destroys the socket sends a TCP RST
 * while the caller is still uploading; the RST races the response away, and the caller sees a
 * connection reset (an `ECONNRESET` on Windows) instead of the 400/401. Draining the remainder
 * first lets the socket close with a clean FIN, so the status is delivered. It stays memory-bounded
 * (chunks are discarded, not held) and time-bounded: a body still arriving past this generous cap
 * is a pathological stream and is cut off with a reset rather than drained without end.
 */
const DRAIN_CAP_BYTES = MAX_REQUEST_BODY_BYTES * 4;

/** A stable JSON body for a gateway condition status, reusing the §12.5 error map (no new identity). */
function conditionBody(status: number): string {
  return JSON.stringify(gatewayConditionBody(status));
}

/**
 * Read and discard the rest of an inbound request, resolving when it ends (or the drain cap is
 * hit). Discarding — not buffering — keeps memory constant, and draining before we close means the
 * subsequent refusal response reaches the caller instead of being lost to a connection reset.
 */
function drainRequest(req: IncomingMessage): Promise<void> {
  return new Promise((resolve) => {
    let discarded = 0;
    const finish = (): void => resolve();
    req.on("error", finish); // a peer reset mid-drain is expected; never crash the server on it
    req.on("end", finish);
    req.on("close", finish);
    req.on("data", (chunk: Buffer) => {
      discarded += chunk.length;
      if (discarded > DRAIN_CAP_BYTES) {
        req.destroy();
        resolve();
      }
    });
    req.resume();
  });
}

/**
 * Send a §12.5 condition response and close the connection. The request stream must already be
 * drained (see {@link drainRequest}) so the close is a clean FIN — closing with unread inbound
 * bytes would RST the socket and race the response away. `Connection: close` is explicit because
 * this connection carried a rejected (partially-read) request and must not be reused.
 */
function refuse(res: ServerResponse, status: number): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.setHeader("connection", "close");
  res.end(conditionBody(status));
}

/** Build a `http.Server` that serves the §12.5 wire protocol against `backend`. */
export function createGatewayServer(backend: GatewayBackend): Server {
  return createServer((req, res) => {
    void (async () => {
      // ── pre-buffer gates (O25) ──────────────────────────────────────────────────────────────
      // Refuse without reading the body: an absent bearer is a 401, and a declared Content-Length
      // over the ceiling is a 400 — so an unauthenticated or oversized caller never forces buffering.
      // Token VALIDITY, version, routing, and Content-Type stay the core's job (single source of
      // truth); this only bounds the memory an un-credentialled request can cost.
      const authorization = req.headers["authorization"];
      const hasBearer =
        typeof authorization === "string" && /^Bearer .+/u.test(authorization);
      if (!hasBearer) {
        await drainRequest(req);
        refuse(res, 401);
        return;
      }
      const declaredLength = Number(req.headers["content-length"] ?? "");
      if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BODY_BYTES) {
        await drainRequest(req);
        refuse(res, 400);
        return;
      }

      // ── bounded buffering ───────────────────────────────────────────────────────────────────
      const chunks: Buffer[] = [];
      let buffered = 0;
      let drained = 0;
      let overflowed = false;
      for await (const chunkValue of req) {
        const chunk = chunkValue as Buffer;
        if (overflowed) {
          // Past the cap we stop buffering but keep discarding, so the 400 below still lands on a
          // cleanly-closing socket. A body that runs past the drain cap is a pathological stream:
          // cut it off (a reset) rather than read it without end.
          drained += chunk.length;
          if (drained > DRAIN_CAP_BYTES) {
            req.destroy();
            break;
          }
          continue;
        }
        buffered += chunk.length;
        if (buffered > MAX_REQUEST_BODY_BYTES) {
          overflowed = true;
          continue;
        }
        chunks.push(chunk);
      }
      if (overflowed) {
        // A lying/absent Content-Length cannot bypass the cap — the body was cut off (never
        // buffered past the cap) and drained so the refusal is delivered, not reset away.
        refuse(res, 400);
        return;
      }
      const body = Buffer.concat(chunks).toString("utf8");
      const headers = new Headers();
      for (const [name, value] of Object.entries(req.headers)) {
        if (value === undefined) continue;
        headers.set(name, Array.isArray(value) ? value.join(", ") : value);
      }
      const url = `http://${req.headers.host ?? "gateway.local"}${req.url ?? "/"}`;
      const request = new Request(url, {
        method: req.method ?? "POST",
        headers,
        ...(body.length > 0 ? { body } : {}),
      });
      let response: Response;
      try {
        response = await handleGatewayRequest(request, backend);
      } catch {
        // The core never throws for a store outage (it maps to 503), so this is only reached if
        // the runtime itself failed to build a response — surface it as unavailability too.
        response = new Response(
          JSON.stringify({
            error: {
              code: "TX402_TRANSPORT",
              details: { causeCategory: "gateway-unavailable" },
            },
          }),
          { status: 503, headers: { "content-type": "application/json" } },
        );
      }
      res.statusCode = response.status;
      response.headers.forEach((value, name) => res.setHeader(name, value));
      res.end(await response.text());
    })().catch(() => {
      // Last-resort guard so a handler rejection never leaves the socket hanging.
      if (!res.headersSent) {
        res.statusCode = 503;
        res.setHeader("content-type", "application/json");
      }
      res.end(
        JSON.stringify({
          error: {
            code: "TX402_TRANSPORT",
            details: { causeCategory: "gateway-unavailable" },
          },
        }),
      );
    });
  });
}

/** A running reference gateway: the server, its base URL, and a `close()` that resolves on shutdown. */
export interface RunningGateway {
  readonly server: Server;
  readonly url: string;
  readonly port: number;
  close(): Promise<void>;
}

/**
 * Start a reference gateway on `host`/`port` (default `127.0.0.1` and an ephemeral port). Resolves
 * once it is listening, with the base URL a `httpGatewaySpendStore` client points at.
 */
export function serveGateway(
  backend: GatewayBackend,
  options: { host?: string; port?: number } = {},
): Promise<RunningGateway> {
  const host = options.host ?? "127.0.0.1";
  const server = createGatewayServer(backend);
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(options.port ?? 0, host, () => {
      const address = server.address() as AddressInfo;
      resolve({
        server,
        port: address.port,
        url: `http://${host}:${address.port}`,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
          }),
      });
    });
  });
}
