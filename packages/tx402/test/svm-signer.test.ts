import type { Transaction } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import type { SolanaSigner } from "../src/core/signers.js";
import { resolveSolanaPublicKey, toTransactionSigner } from "../src/solana/signer.js";

const PUBLIC_KEY = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const FEE_PAYER = "11111111111111111111111111111111";
const context = {
  requestId: "svm-contract",
  phase: "sign" as const,
  network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
  scheme: "exact",
};

function adapter(signer: SolanaSigner) {
  return toTransactionSigner({
    signer,
    plan: {
      publicKey: PUBLIC_KEY,
      feePayer: FEE_PAYER,
      mint: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
      sourceTokenAccount: "7qV4R7W7GnaQE6atSbiHCVEcM5yqR9mWgvrRQ9HhABaD",
      destinationTokenAccount: "5ddg6W32pyQCTdKpA5qkAVH9k4WVsCWkTBLn5Pdd9QZ8",
      recipient: PUBLIC_KEY,
      amountAtomic: "50000",
      decimals: 6,
      lastValidBlockHeight: "99",
    },
    presentation: {
      network: context.network,
      assetId: `${context.network}/token:4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`,
      assetSymbol: "USDC",
      amountAtomic: "50000",
      amountDecimal: "0.05",
      recipient: PUBLIC_KEY,
      resourceHost: "merchant.example",
      feePayer: FEE_PAYER,
      requestHash: `sha256:${"ab".repeat(32)}`,
    },
    lifetimeSeconds: 60,
    record: { signCount: 0, expiresAtEpochMs: 0, serializedBytes: 0 },
    context,
  });
}

describe("Solana signer contract", () => {
  it("memoizes a valid public key and does not cache a failed lookup", async () => {
    const getPublicKey = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new Error("transient"))
      .mockResolvedValue(PUBLIC_KEY);
    const signer: SolanaSigner = {
      kind: "solana",
      getPublicKey,
      signTransaction: vi.fn(),
    };
    await expect(resolveSolanaPublicKey(signer, context)).rejects.toMatchObject({
      code: "TX402_SIGNER",
    });
    await expect(resolveSolanaPublicKey(signer, context)).resolves.toBe(PUBLIC_KEY);
    await expect(resolveSolanaPublicKey(signer, context)).resolves.toBe(PUBLIC_KEY);
    expect(getPublicKey).toHaveBeenCalledTimes(2);
  });

  it("types a malformed public key before any transaction can be built", async () => {
    const signer: SolanaSigner = {
      kind: "solana",
      getPublicKey: () => Promise.resolve("not-base58"),
      signTransaction: vi.fn(),
    };
    await expect(resolveSolanaPublicKey(signer, context)).rejects.toMatchObject({
      code: "TX402_SIGNER",
      details: { signerKind: "solana", causeCategory: "address-unavailable" },
    });
  });

  it("rejects malformed transaction bytes before invoking the external signer", async () => {
    const signTransaction = vi.fn<() => Promise<Uint8Array>>();
    const signer: SolanaSigner = {
      kind: "solana",
      getPublicKey: () => Promise.resolve(PUBLIC_KEY),
      signTransaction,
    };
    const malformed = {
      messageBytes: new Uint8Array([1, 2, 3]),
      signatures: { [PUBLIC_KEY]: null },
    } as unknown as Transaction;
    await expect(
      adapter(signer).signTransactions([malformed as never]),
    ).rejects.toMatchObject({
      code: "TX402_SIGNER",
      details: { causeCategory: "transaction-invalid" },
    });
    expect(signTransaction).not.toHaveBeenCalled();
  });

  it("rejects an oversized serialized transaction before invoking the signer", async () => {
    const signTransaction = vi.fn<() => Promise<Uint8Array>>();
    const signer: SolanaSigner = {
      kind: "solana",
      getPublicKey: () => Promise.resolve(PUBLIC_KEY),
      signTransaction,
    };
    const oversized = {
      messageBytes: new Uint8Array(1300),
      signatures: { [PUBLIC_KEY]: null },
    } as unknown as Transaction;
    await expect(
      adapter(signer).signTransactions([oversized as never]),
    ).rejects.toMatchObject({
      code: "TX402_SIGNER",
      details: { causeCategory: "transaction-too-large" },
    });
    expect(signTransaction).not.toHaveBeenCalled();
  });

  it("rejects batches before invoking the signer", async () => {
    const signTransaction = vi.fn<() => Promise<Uint8Array>>();
    const signer: SolanaSigner = {
      kind: "solana",
      getPublicKey: () => Promise.resolve(PUBLIC_KEY),
      signTransaction,
    };
    await expect(adapter(signer).signTransactions([])).rejects.toMatchObject({
      details: { causeCategory: "duplicate-signature-request" },
    });
    expect(signTransaction).not.toHaveBeenCalled();
  });
});
