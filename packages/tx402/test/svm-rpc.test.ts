import { createSvmRpcStub, type SvmRpcStub } from "@tx402-dev/svm-rpc-stub";
import { afterEach, describe, expect, it } from "vitest";

import { derivePaymentAtas } from "../src/solana/signer.js";
import { SvmRpcPool } from "../src/solana/rpc.js";

const GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const OWNER = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const RECIPIENT = "11111111111111111111111111111111";
const stubs: SvmRpcStub[] = [];

afterEach(async () => {
  await Promise.all(stubs.splice(0).map((stub) => stub.close()));
});

async function stub(amount = "50000"): Promise<SvmRpcStub> {
  const atas = await derivePaymentAtas({ mint: MINT, payer: OWNER, recipient: RECIPIENT });
  const created = await createSvmRpcStub({
    genesisHash: GENESIS,
    mint: MINT,
    tokenAccounts: {
      [atas.source]: { owner: OWNER, mint: MINT, amount, decimals: 6 },
    },
  });
  stubs.push(created);
  return created;
}

describe("SvmRpcPool", () => {
  it("validates genesis before reading the canonical ATA balance", async () => {
    const rpc = await stub("123456");
    await expect(
      new SvmRpcPool([rpc.url]).readBalance({
        genesisHash: GENESIS,
        mint: MINT,
        owner: OWNER,
        decimals: 6,
        nowEpochMs: 1,
      }),
    ).resolves.toMatchObject({ balanceAtomic: 123456n });
    expect(rpc.calls.map((call) => call.method)).toEqual([
      "getGenesisHash",
      "getAccountInfo",
    ]);
  });

  it("opens a wrong-cluster endpoint and falls through to a healthy secondary", async () => {
    const wrong = await stub();
    const healthy = await stub("70000");
    wrong.setMode("wrong-cluster");
    await expect(
      new SvmRpcPool([wrong.url, healthy.url]).readBalance({
        genesisHash: GENESIS,
        mint: MINT,
        owner: OWNER,
        decimals: 6,
        nowEpochMs: 10,
      }),
    ).resolves.toMatchObject({ balanceAtomic: 70000n });
    expect(wrong.calls.map((call) => call.method)).toEqual(["getGenesisHash"]);
  });

  it("races a hanging primary deadline and uses the secondary", async () => {
    const hanging = await stub();
    const healthy = await stub("80000");
    hanging.setMode("hang");
    await expect(
      new SvmRpcPool([hanging.url, healthy.url], { timeoutMs: 25 }).readBalance({
        genesisHash: GENESIS,
        mint: MINT,
        owner: OWNER,
        decimals: 6,
        nowEpochMs: 10,
      }),
    ).resolves.toMatchObject({ balanceAtomic: 80000n });
  });

  it("uses the secondary when the primary ATA contents are invalid", async () => {
    const atas = await derivePaymentAtas({
      mint: MINT,
      payer: OWNER,
      recipient: RECIPIENT,
    });
    const invalid = await createSvmRpcStub({
      genesisHash: GENESIS,
      mint: MINT,
      tokenAccounts: {
        [atas.source]: { owner: RECIPIENT, mint: MINT, amount: "90000", decimals: 6 },
      },
    });
    stubs.push(invalid);
    const healthy = await stub("85000");
    await expect(
      new SvmRpcPool([invalid.url, healthy.url]).readBalance({
        genesisHash: GENESIS,
        mint: MINT,
        owner: OWNER,
        decimals: 6,
        nowEpochMs: 10,
      }),
    ).resolves.toMatchObject({ balanceAtomic: 85000n });
    expect(invalid.calls.map((call) => call.method)).toEqual([
      "getGenesisHash",
      "getAccountInfo",
    ]);
  });

  it("reports a stable mismatch category and never asks that endpoint for an account", async () => {
    const wrong = await stub();
    wrong.setMode("wrong-cluster");
    await expect(
      new SvmRpcPool([wrong.url]).readBalance({
        genesisHash: GENESIS,
        mint: MINT,
        owner: OWNER,
        decimals: 6,
        nowEpochMs: 10,
      }),
    ).rejects.toMatchObject({ failure: "genesis-hash-mismatch" });
    expect(wrong.calls.map((call) => call.method)).toEqual(["getGenesisHash"]);
  });

  it("treats an absent canonical ATA as a zero balance", async () => {
    const rpc = await createSvmRpcStub({ genesisHash: GENESIS, mint: MINT });
    stubs.push(rpc);
    await expect(
      new SvmRpcPool([rpc.url]).readBalance({
        genesisHash: GENESIS,
        mint: MINT,
        owner: OWNER,
        decimals: 6,
        nowEpochMs: 1,
      }),
    ).resolves.toMatchObject({ balanceAtomic: 0n });
  });

  it.each(["rpc-error", "http-error", "garbage"] as const)(
    "categorizes %s without exposing provider text",
    async (mode) => {
      const rpc = await stub();
      rpc.setMode(mode);
      await expect(
        new SvmRpcPool([rpc.url]).validatedRpcUrl(GENESIS, 1),
      ).rejects.toBeInstanceOf(Error);
    },
  );

  it("rejects an empty endpoint list", async () => {
    await expect(new SvmRpcPool([]).validatedRpcUrl(GENESIS, 1)).rejects.toMatchObject({
      failure: "transport",
    });
  });
});
