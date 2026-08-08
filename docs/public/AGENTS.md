# AGENTS.md

Guidance for AI agents and automated tools working with **tx402** — the spend-governance layer for x402 buyers, a non-custodial SDK in TypeScript and Python.

## Overview

tx402 wraps an HTTP client and completes the `402 Payment Required` handshake for autonomous agents. It enforces spend policy — per-request caps, hourly/cumulative budgets, domain and chain allowlists, and an atomic reservation — **before any key is signed**, then deterministically routes across the chains a merchant offered (Base and Solana), fails over RPC endpoints, and returns typed, ambiguity-safe outcomes. It is buyer-side only: it never custodies funds, never calls a facilitator's verify/settle, and never bridges or swaps.

- Runtimes: TypeScript (Node 20+) and Python (3.10+)
- Package: `tx402` (unscoped) on npm and PyPI
- License: Apache-2.0
- Source: https://github.com/neogeeks/tx402

## Installation

Chain support is optional, so the install command depends on the chain you pay on:

```bash
# TypeScript (Node 20+)
npm install tx402                                                   # core + CLI, no chain
npm install tx402 @x402/evm viem                                    # Base / EVM
npm install tx402 @solana-program/token @solana/kit @x402/svm viem # Solana

# Python (3.10+)
pip install tx402            # core, no chain
pip install "tx402[evm]"     # Base / EVM
pip install "tx402[solana]"  # Solana
pip install "tx402[all]"     # both
```

## Configuration

A client is configured with signers and a spend policy; the policy is enforced before any signer runs.

```ts
import { createTx402Client } from "tx402";

const tx402 = createTx402Client({
  signers: { evm, solana },
  policy: {
    maxPerRequest: "0.50 USDC", // per-request cap
    maxPerHour: "10.00 USDC", // cumulative hourly budget
    allowedNetworks: ["eip155:8453", "solana:mainnet"], // chain allowlist
  },
});
```

Amounts are always integer atomic units (never floats). Additional options include a domain allowlist and `maxPaidAttempts`; see the full [configuration reference](https://docs.tx402.io/reference/configuration/).

## Usage

```ts
// Drop-in: completes the 402 handshake within policy, or returns a typed error.
const res = await tx402.fetch(url, init);
```

Command line:

```bash
# Plan a payment without signing (no key is touched):
npx tx402 call <url> --max-spend "0.10 USDC" --dry-run
```

See the [Quickstart](https://docs.tx402.io/start/quickstart/) for an end-to-end paid call.

## Developing tx402 (in the repository)

- Install: `pnpm install` (the workspace uses Node 22; the published SDK targets Node 20+)
- Build: `pnpm --filter tx402 build`
- Full check (lint, types, tests, conformance, size, docs): `pnpm check`
- Tests: `pnpm test` (TypeScript); `uv run pytest` inside `packages/tx402-python`
- Docs site: `pnpm docs:dev` / `pnpm docs:build`

## Conventions (non-negotiable)

- Money is always integer atomic units — never a float.
- Policy evaluation and budget reservation happen **before** any signer call.
- Never log or embed signatures, keys, or authorization payloads.
- The buyer never calls a facilitator's verify/settle; the merchant owns settlement.
- TypeScript and Python are held to identical behavior by 73 shared conformance vectors.

## Security

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/neogeeks/tx402/security/advisories/new); see the [security policy](https://github.com/neogeeks/tx402/blob/main/SECURITY.md).

## Documentation

Full docs: https://docs.tx402.io — a clean Markdown version of any page is available by appending `.md` to its path, or by requesting the page with `Accept: text/markdown`. Machine indexes: https://docs.tx402.io/llms.txt and https://docs.tx402.io/llms-full.txt
