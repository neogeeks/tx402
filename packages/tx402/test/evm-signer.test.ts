/**
 * Signer contract suite (SPEC §12.1 "Contract", §6.6, §7.1, SEC-001, SEC-003).
 *
 * The adapter is the last place tx402 can see what is about to be signed, so most of what is
 * asserted here is refusal: an EIP-712 message that does not match the approved plan must not
 * reach the caller's signer at all.
 */

import { randomBytes } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import { chainFamily, loadChainAdapter } from "../src/core/chain.js";
import { SignerError } from "../src/core/errors.js";
import { isEvmSigner, isSolanaSigner } from "../src/core/signers.js";
import type { EvmSigner, EvmTypedDataRequest } from "../src/core/signers.js";
import { resolveEvmAddress, toClientEvmSigner } from "../src/evm/signer.js";
import { keypairToSolanaSigner, privateKeyToEvmSigner } from "../src/signers/index.js";

const PAYER = "0x1111111111111111111111111111111111111111" as const;
const PAY_TO = "0x2222222222222222222222222222222222222222";
const TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const LIFETIME_SECONDS = 60;
const CONTEXT = { requestId: "signer-test", phase: "sign" } as const;

/** Wall-clock seconds, because the adapter now derives its window from the real clock. */
const nowSeconds = () => Math.floor(Date.now() / 1000);

const PLAN = {
  chainId: 8453,
  verifyingContract: TOKEN,
  domainName: "USD Coin",
  domainVersion: "2",
  from: PAYER,
  to: PAY_TO,
  valueAtomic: "50000",
  lifetimeSeconds: LIFETIME_SECONDS,
} as const;

const PRESENTATION = {
  network: "eip155:8453",
  assetId: "eip155:8453/erc20:" + TOKEN,
  assetSymbol: "USDC",
  amountAtomic: "50000",
  amountDecimal: "0.05",
  recipient: PAY_TO,
  resourceHost: "api.example.com",
  domainName: "USD Coin",
  requestHash: `sha256:${"a".repeat(64)}`,
} as const;

/** Built by concatenation so the cast is unambiguously load-bearing. */
const FAKE_SIGNATURE = ("0x" + "cd".repeat(65)) as `0x${string}`;

const TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

function typedData(overrides: { domain?: object; message?: object } = {}) {
  return {
    domain: {
      name: "USD Coin",
      version: "2",
      chainId: 8453,
      verifyingContract: TOKEN,
      ...overrides.domain,
    },
    types: TYPES as unknown as Record<string, unknown>,
    primaryType: "TransferWithAuthorization",
    message: {
      from: PAYER,
      to: PAY_TO,
      value: 50_000n,
      validAfter: 0n,
      validBefore: BigInt(nowSeconds() + LIFETIME_SECONDS),
      nonce: `0x${"ab".repeat(32)}`,
      ...overrides.message,
    },
  };
}

function fakeSigner(): EvmSigner & { calls: EvmTypedDataRequest[] } {
  const calls: EvmTypedDataRequest[] = [];
  return {
    kind: "evm",
    calls,
    getAddress: () => Promise.resolve(PAYER),
    signTypedData: (request) => {
      calls.push(request);
      return Promise.resolve(FAKE_SIGNATURE);
    },
  };
}

function adapt(signer: EvmSigner, record = { signCount: 0, expiresAtEpochMs: 0 }) {
  return {
    record,
    client: toClientEvmSigner({
      signer,
      address: PAYER,
      plan: PLAN,
      presentation: PRESENTATION,
      record,
      context: CONTEXT,
    }),
  };
}

describe("EvmSigner address resolution", () => {
  it("resolves once per signer and caches the result", async () => {
    const getAddress = vi.fn(() => Promise.resolve(PAYER));
    const signer: EvmSigner = { kind: "evm", getAddress, signTypedData: vi.fn() };

    await expect(resolveEvmAddress(signer, CONTEXT)).resolves.toBe(PAYER);
    await expect(resolveEvmAddress(signer, CONTEXT)).resolves.toBe(PAYER);

    // ADR-010 decision 5 (amended at S5): construction is synchronous, so the resolution
    // happens on first use — but only once, no matter how many payments follow.
    expect(getAddress).toHaveBeenCalledOnce();
  });

  it("types a malformed or failing address lookup as SignerError and does not cache it", async () => {
    const getAddress = vi
      .fn<() => Promise<`0x${string}`>>()
      .mockRejectedValueOnce(new Error("kms unreachable"))
      .mockResolvedValue(PAYER);
    const signer: EvmSigner = { kind: "evm", getAddress, signTypedData: vi.fn() };

    await expect(resolveEvmAddress(signer, CONTEXT)).rejects.toMatchObject({
      code: "TX402_SIGNER",
      details: { signerKind: "evm", causeCategory: "address-unavailable" },
    });
    // A transient failure must not poison the signer for the life of the process.
    await expect(resolveEvmAddress(signer, CONTEXT)).resolves.toBe(PAYER);

    const malformed: EvmSigner = {
      kind: "evm",
      getAddress: () => Promise.resolve("0xnot-an-address" as `0x${string}`),
      signTypedData: vi.fn(),
    };
    await expect(resolveEvmAddress(malformed, CONTEXT)).rejects.toBeInstanceOf(SignerError);
  });
});

describe("EvmSigner plan enforcement", () => {
  it("forwards a matching authorization and presents it in human-readable form", async () => {
    const signer = fakeSigner();
    const { client, record } = adapt(signer);

    const expected = typedData();
    const signature = await client.signTypedData(expected);

    expect(signature).toMatch(/^0x[0-9a-f]+$/u);
    expect(record.signCount).toBe(1);
    expect(record.expiresAtEpochMs).toBe(Number(expected.message.validBefore) * 1000);

    // SPEC §6.6: the request presented to an external signer carries the domain, asset,
    // atomic and decimal amounts, recipient, network, expiry, and request hash.
    const presented = signer.calls[0]?.presentation;
    expect(presented).toEqual({
      ...PRESENTATION,
      expiresAt: new Date(Number(expected.message.validBefore) * 1000).toISOString(),
    });
    expect(signer.calls[0]?.types.TransferWithAuthorization).toHaveLength(6);
  });

  it("refuses a second signature for one authorization", async () => {
    const signer = fakeSigner();
    const { client } = adapt(signer);

    await client.signTypedData(typedData());
    // ADR-003: one authorization per attempt. Two signatures for one reservation would be
    // two spendable authorizations.
    await expect(client.signTypedData(typedData())).rejects.toMatchObject({
      code: "TX402_SIGNER",
      details: { causeCategory: "duplicate-signature-request" },
    });
    expect(signer.calls).toHaveLength(1);
  });

  it("refuses every deviation from the approved plan before the signer is invoked", async () => {
    const deviations: [string, { domain?: object; message?: object }][] = [
      ["wrong chain", { domain: { chainId: 1 } }],
      ["wrong token", { domain: { verifyingContract: PAY_TO } }],
      ["wrong domain name", { domain: { name: "Not USD Coin" } }],
      ["wrong domain version", { domain: { version: "1" } }],
      ["wrong payer", { message: { from: PAY_TO } }],
      ["wrong recipient", { message: { to: PAYER } }],
      ["wrong amount", { message: { value: 50_001n } }],
      ["delayed start", { message: { validAfter: 5n } }],
      [
        "lifetime beyond the bound",
        { message: { validBefore: BigInt(nowSeconds() + LIFETIME_SECONDS + 120) } },
      ],
      ["already expired", { message: { validBefore: BigInt(nowSeconds() - 10) } }],
      ["short nonce", { message: { nonce: "0xdead" } }],
      ["non-integer amount", { message: { value: "fifty thousand" } }],
      ["non-string recipient", { message: { to: 42 } }],
    ];

    for (const [label, overrides] of deviations) {
      const signer = fakeSigner();
      const { client } = adapt(signer);
      await expect(client.signTypedData(typedData(overrides)), label).rejects.toMatchObject(
        { code: "TX402_SIGNER", details: { signerKind: "evm" } },
      );
      expect(signer.calls, label).toHaveLength(0);
    }
  });

  it("accepts an authorization stamped before the window is derived", async () => {
    // Regression. Upstream reads its own clock inside `createPaymentPayload`, so the message
    // is always stamped *before* this adapter checks it. When the bound was computed ahead of
    // that call instead, any second boundary falling between the two reads made `validBefore`
    // exceed it by one and rejected a perfectly valid authorization — rare, random, and a
    // burnt reservation each time. Deriving the bound from the later clock removes the race:
    // a message stamped up to `lifetime - 1` seconds earlier is still inside the window.
    const signer = fakeSigner();
    const { client } = adapt(signer);
    const start = 1_785_000_000_000;

    vi.useFakeTimers();
    try {
      vi.setSystemTime(start);
      const stamped = typedData();
      // Time passes — including a second boundary — between upstream stamping and the check.
      vi.setSystemTime(start + 1_500);

      await expect(client.signTypedData(stamped)).resolves.toMatch(/^0x/u);
    } finally {
      vi.useRealTimers();
    }
    expect(signer.calls).toHaveLength(1);
  });

  it("rejects an unexpected primary type and malformed type definitions", async () => {
    const signer = fakeSigner();
    const { client } = adapt(signer);
    await expect(
      client.signTypedData({ ...typedData(), primaryType: "Permit" }),
    ).rejects.toBeInstanceOf(SignerError);

    await expect(
      client.signTypedData({
        ...typedData(),
        types: { TransferWithAuthorization: [{ name: "from" }] },
      }),
    ).rejects.toBeInstanceOf(SignerError);
    expect(signer.calls).toHaveLength(0);
  });

  it("never surfaces the signer's own failure text", async () => {
    const signer: EvmSigner = {
      kind: "evm",
      getAddress: () => Promise.resolve(PAYER),
      signTypedData: () =>
        Promise.reject(new Error("device 0xSEEDED-KEY-PATH refused: seeded payload")),
    };
    const { client } = adapt(signer);

    const error = await client
      .signTypedData(typedData())
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(SignerError);
    // SEC-003: a signer's message may name a key path, a device, or the payload itself.
    expect(JSON.stringify((error as SignerError).toJSON())).not.toContain(
      "SEEDED-KEY-PATH",
    );
    expect((error as SignerError).details).toEqual({
      signerKind: "evm",
      causeCategory: "signer-rejected",
    });
  });

  it("rejects a signature that is not hex", async () => {
    const signer: EvmSigner = {
      kind: "evm",
      getAddress: () => Promise.resolve(PAYER),
      signTypedData: () => Promise.resolve("not-a-signature" as `0x${string}`),
    };
    const { client } = adapt(signer);
    await expect(client.signTypedData(typedData())).rejects.toMatchObject({
      details: { causeCategory: "malformed-signature" },
    });
  });
});

describe("private-key convenience adapter (SEC-001)", () => {
  // Generated per run. No key material is committed to the repository.
  const key = ("0x" + randomBytes(32).toString("hex")) as `0x${string}`;

  it("produces a working EvmSigner without exposing the key", async () => {
    const signer = privateKeyToEvmSigner(key);
    const address = await signer.getAddress();

    expect(signer.kind).toBe("evm");
    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/u);

    const signature = await signer.signTypedData({
      ...typedData(),
      types: TYPES,
      presentation: { ...PRESENTATION, expiresAt: "2026-08-02T00:00:00.000Z" },
    });
    expect(signature).toMatch(/^0x[0-9a-f]{130}$/u);

    // The key must not be reachable from the object, its serialization, or its inspection.
    expect(JSON.stringify(signer)).not.toContain(key.slice(2));
    expect(signer.toJSON()).toEqual({ kind: "evm", address });
    expect(Object.values(signer).join(" ")).not.toContain(key.slice(2));
  });

  it("rejects a malformed key before a chain library can quote it", () => {
    expect(() => privateKeyToEvmSigner("0xshort")).toThrow(TypeError);
    expect(() => privateKeyToEvmSigner(undefined as unknown as `0x${string}`)).toThrow(
      TypeError,
    );
  });
});

describe("keypair convenience adapter, Solana (SEC-001)", () => {
  // A throwaway keypair derived from a fixed seed for this test alone. It holds nothing on
  // any cluster, and the identical bytes appear in the Python suite
  // (`tests/test_signers.py::SOLANA_KEYPAIR`) so the two languages are held to the same
  // derived address from the same input.
  const KEYPAIR = [
    14, 200, 93, 200, 99, 239, 157, 82, 111, 247, 30, 2, 138, 61, 188, 29, 138, 92, 85, 5,
    220, 150, 210, 158, 61, 73, 122, 94, 137, 34, 216, 241, 200, 103, 77, 26, 108, 138, 48,
    143, 33, 107, 244, 199, 17, 251, 21, 8, 84, 91, 77, 73, 60, 57, 114, 66, 52, 8, 179,
    238, 103, 132, 135, 46,
  ];
  const ADDRESS = "EVHuBQEV9EL3kVzBndVQTKvhdHbAdNBkMfJBteUyhU13";

  const request = (messageBytes: Uint8Array) => ({
    messageBytes,
    transactionBytes: new Uint8Array(16).fill(0xff),
    presentation: PRESENTATION as never,
  });

  it("accepts the JSON array `solana-keygen` writes, raw bytes, and a number array alike", async () => {
    const fromJson = await keypairToSolanaSigner(JSON.stringify(KEYPAIR));
    const fromBytes = await keypairToSolanaSigner(Uint8Array.from(KEYPAIR));
    const fromArray = await keypairToSolanaSigner(KEYPAIR);

    for (const signer of [fromJson, fromBytes, fromArray]) {
      expect(signer.kind).toBe("solana");
      expect(await signer.getPublicKey()).toBe(ADDRESS);
    }
  });

  it("produces a 64-byte signature without exposing the keypair", async () => {
    const signer = await keypairToSolanaSigner(KEYPAIR);
    const signature = await signer.signTransaction(request(new Uint8Array([0x80, 1, 2])));

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature).toHaveLength(64);
    expect(signer.toJSON()).toEqual({ kind: "solana", address: ADDRESS });
    expect(JSON.stringify(signer)).not.toContain(String(KEYPAIR[0]));
  });

  it("signs messageBytes and nothing else", async () => {
    // Ed25519 is deterministic, so the same `messageBytes` under two different surrounding
    // requests must sign identically. If the adapter ever folded `transactionBytes` or the
    // presentation in, these would diverge — and it would be signing something other than
    // what the runtime verifies.
    const signer = await keypairToSolanaSigner(KEYPAIR);
    const message = new Uint8Array([0x80, 9, 9, 9]);

    const first = await signer.signTransaction(request(message));
    const second = await signer.signTransaction({
      messageBytes: message,
      transactionBytes: new Uint8Array(32),
      presentation: { different: true } as never,
    });

    expect(Buffer.from(first).equals(Buffer.from(second))).toBe(true);
  });

  it("rejects anything that is not 64 keypair bytes, without quoting it", async () => {
    const secret = JSON.stringify(Array<number>(63).fill(7));
    await expect(keypairToSolanaSigner(secret)).rejects.toThrow(/64 keypair bytes/u);
    await expect(keypairToSolanaSigner(secret)).rejects.not.toThrow(secret);

    await expect(keypairToSolanaSigner("not json")).rejects.toThrow(TypeError);
    await expect(keypairToSolanaSigner("{}")).rejects.toThrow(TypeError);
    await expect(keypairToSolanaSigner(undefined as unknown as string)).rejects.toThrow(
      TypeError,
    );
    await expect(
      keypairToSolanaSigner(JSON.stringify(Array<number>(64).fill(999))),
    ).rejects.toThrow(/range/u);
  });
});

describe("signer contract guards (SPEC §7.1/§7.2)", () => {
  it("recognizes structurally valid signers and nothing else", () => {
    // Structural, not `instanceof`: a caller's signer is an object literal, a wrapped viem
    // account, or a proxy to a remote service, and none share a prototype with tx402's.
    expect(
      isEvmSigner({ kind: "evm", getAddress: () => {}, signTypedData: () => {} }),
    ).toBe(true);
    expect(
      isSolanaSigner({ kind: "solana", getPublicKey: () => {}, signTransaction: () => {} }),
    ).toBe(true);

    for (const candidate of [
      null,
      undefined,
      "evm",
      42,
      {},
      { kind: "evm" },
      { kind: "evm", getAddress: () => {} },
      { kind: "solana", getAddress: () => {}, signTypedData: () => {} },
    ]) {
      expect(isEvmSigner(candidate), JSON.stringify(candidate ?? null)).toBe(false);
      expect(isSolanaSigner(candidate), JSON.stringify(candidate ?? null)).toBe(false);
    }
  });

  it("loads only implemented chain-family adapters", async () => {
    expect(chainFamily("eip155:8453")).toBe("eip155");
    expect(chainFamily("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")).toBe("solana");
    await expect(loadChainAdapter("solana")).resolves.toMatchObject({ family: "solana" });
    await expect(loadChainAdapter("cosmos")).resolves.toBeUndefined();
    await expect(loadChainAdapter("eip155")).resolves.toMatchObject({ family: "eip155" });
  });
});
