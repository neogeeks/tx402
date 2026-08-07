/** Faithful fixture harness for the Solana RPC surface used by tx402 and ExactSvmScheme. */

import { once } from "node:events";
import { createServer } from "node:http";

const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const DEFAULT_GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const DEFAULT_BLOCKHASH = "11111111111111111111111111111111";

/** Minimal initialized SPL Mint account (82 bytes), enough for upstream `fetchMint`. */
function mintData(decimals) {
  const bytes = Buffer.alloc(82);
  bytes.writeUInt32LE(0, 0); // mintAuthority: None
  bytes.writeBigUInt64LE(0n, 36); // supply
  bytes[44] = decimals;
  bytes[45] = 1; // isInitialized
  bytes.writeUInt32LE(0, 46); // freezeAuthority: None
  return bytes.toString("base64");
}

export async function createSvmRpcStub(options) {
  const {
    genesisHash = DEFAULT_GENESIS,
    wrongGenesisHash = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
    mint,
    decimals = 6,
    tokenAccounts = {},
    mode: initialMode = "ok",
    port = 0,
  } = options;
  let mode = initialMode;
  const calls = [];
  const hung = new Set();
  const accounts = new Map(Object.entries(tokenAccounts));

  const server = createServer((request, response) => {
    void (async () => {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      if (mode === "hang") {
        hung.add(response);
        response.on("close", () => hung.delete(response));
        return;
      }
      if (mode === "http-error") {
        response.writeHead(503, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: "stub-unavailable" }));
        return;
      }
      if (mode === "garbage") {
        response.writeHead(200, { "content-type": "application/json" });
        response.end("<not json>");
        return;
      }
      let envelope;
      try {
        envelope = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        response.writeHead(400).end();
        return;
      }
      const { id = null, method, params = [] } = envelope ?? {};
      calls.push({ method, params });
      const send = (body) => {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ jsonrpc: "2.0", id, ...body }));
      };
      if (mode === "rpc-error") {
        send({ error: { code: -32000, message: "stub-configured-error" } });
        return;
      }
      switch (method) {
        case "getGenesisHash":
          send({ result: mode === "wrong-cluster" ? wrongGenesisHash : genesisHash });
          return;
        case "getLatestBlockhash":
          send({
            result: {
              context: { slot: 1 },
              value: { blockhash: DEFAULT_BLOCKHASH, lastValidBlockHeight: 999999 },
            },
          });
          return;
        case "getAccountInfo": {
          const accountAddress = String(params[0] ?? "");
          if (accountAddress === mint) {
            send({
              result: {
                context: { apiVersion: "2.0.0", slot: 1 },
                value: {
                  data: [mintData(decimals), "base64"],
                  executable: false,
                  lamports: 1,
                  owner: TOKEN_PROGRAM,
                  rentEpoch: 0,
                  space: 82,
                },
              },
            });
            return;
          }
          const token = accounts.get(accountAddress);
          send({
            result: {
              context: { apiVersion: "2.0.0", slot: 1 },
              value:
                token === undefined
                  ? null
                  : {
                      data: {
                        program: "spl-token",
                        parsed: {
                          type: "account",
                          info: {
                            owner: token.owner,
                            mint: token.mint,
                            tokenAmount: {
                              amount: token.amount,
                              decimals: token.decimals ?? decimals,
                              uiAmount: null,
                              uiAmountString: "0",
                            },
                          },
                        },
                        space: 165,
                      },
                      executable: false,
                      lamports: 1,
                      owner: TOKEN_PROGRAM,
                      rentEpoch: 0,
                      space: 165,
                    },
            },
          });
          return;
        }
        default:
          send({ error: { code: -32601, message: "method outside fixture surface" } });
      }
    })();
  });
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
  const bound = server.address();
  if (typeof bound !== "object" || bound === null) throw new Error("stub did not bind");
  return {
    url: `http://127.0.0.1:${bound.port}`,
    port: bound.port,
    genesisHash,
    calls,
    get mode() {
      return mode;
    },
    setMode(next) {
      mode = next;
    },
    setTokenAccount(accountAddress, account) {
      accounts.set(accountAddress, account);
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
