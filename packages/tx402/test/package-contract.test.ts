import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  PACKAGE_NAME,
  PROTOCOL_HEADERS,
  RESERVED_REQUEST_HEADERS,
  X402_PROTOCOL_VERSION,
} from "../src/index.js";

const pkg = JSON.parse(
  readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"),
) as {
  name: string;
  bin: Record<string, string>;
  exports: Record<string, unknown>;
  dependencies: Record<string, string>;
};

/**
 * Guards the decisions in ADR-009 (package identity) and ADR-004 (protocol boundary).
 * These are cheap to assert and expensive to get wrong after publish.
 */
describe("package contract", () => {
  it("publishes under the unscoped name tx402 on npm (ADR-009)", () => {
    expect(pkg.name).toBe("tx402");
    expect(pkg.name).toBe(PACKAGE_NAME);
    expect(pkg.name.startsWith("@")).toBe(false);
  });

  it("exposes the CLI via bin so npx tx402 resolves (ADR-009)", () => {
    expect(pkg.bin).toHaveProperty("tx402");
  });

  it("keeps chain adapters and signers behind subpath exports (ADR-008)", () => {
    expect(Object.keys(pkg.exports)).toEqual(
      expect.arrayContaining([".", "./evm", "./solana", "./signers"]),
    );
  });

  it("keeps the core import path free of chain dependencies (ADR-008)", () => {
    // Only the protocol codec may be a hard dependency. viem, @solana/kit, @x402/evm and
    // @x402/svm must stay optional peers so `import "tx402"` never pulls them in.
    expect(Object.keys(pkg.dependencies)).toEqual(["@x402/core"]);
  });
});

describe("subpath export surface", () => {
  it("exposes the Base adapter and its signer contract from tx402/evm", async () => {
    const evm = await import("../src/evm/index.js");

    // The entry point a caller actually imports. Asserting on it keeps a re-export from
    // being dropped silently, which a test importing submodules directly would never catch.
    expect(Object.keys(evm).sort()).toEqual([
      "BALANCE_OF_SELECTOR",
      "EvmRpcError",
      "EvmRpcPool",
      "SUPPORTED_ASSET_TRANSFER_METHOD",
      "createEvmChainAdapter",
      "encodeBalanceOfCallData",
      "isEvmSigner",
      "planExactEvmAuthorization",
      "resolveEvmAddress",
      "toClientEvmSigner",
    ]);
    expect(evm.createEvmChainAdapter()).toMatchObject({ family: "eip155" });
  });

  it("exposes only the two key-loading convenience adapters from tx402/signers", async () => {
    const signers = await import("../src/signers/index.js");
    // SEC-001: the raw-key path is opt-in and lives nowhere else. This list is asserted
    // exactly, not by `toContain`, so that a *new* export holding key material fails here
    // and has to be justified rather than arriving unnoticed.
    expect(Object.keys(signers).sort()).toEqual([
      "keypairToSolanaSigner",
      "privateKeyToEvmSigner",
    ]);
  });
});

describe("protocol constants", () => {
  it("targets x402 protocol v2 only (ADR-004)", () => {
    expect(X402_PROTOCOL_VERSION).toBe(2);
  });

  it("uses the v2 header names, not the v1 X-PAYMENT forms (ADR-004)", () => {
    expect(PROTOCOL_HEADERS).toEqual({
      paymentRequired: "PAYMENT-REQUIRED",
      paymentSignature: "PAYMENT-SIGNATURE",
      paymentResponse: "PAYMENT-RESPONSE",
    });
    for (const header of Object.values(PROTOCOL_HEADERS)) {
      expect(header.startsWith("X-")).toBe(false);
    }
  });

  it("reserves every protocol header against caller override (SPEC §6.1)", () => {
    expect(RESERVED_REQUEST_HEADERS).toEqual(
      expect.arrayContaining(Object.values(PROTOCOL_HEADERS)),
    );
  });
});
