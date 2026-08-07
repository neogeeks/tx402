# Changelog

All notable changes to `tx402` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/) under the policy in [VERSIONING.md](VERSIONING.md).

**The TypeScript and Python packages share this changelog**, because they share a version number
and are released from the same commit. An entry applies to both languages unless it says otherwise.

Breaking changes appear under a `### Breaking` heading — including during 0.x, where SemVer permits
a minor to break you but this project still refuses to let it happen quietly.

## [Unreleased]

## [0.1.0] - 2026-08-06

First functional release. The `0.0.0` that preceded it on npm and PyPI was an inert placeholder
published only to hold the name.

### Added

- **The buyer-side SDK, in TypeScript and Python.** `createTx402Client` / `Tx402Client` /
  `AsyncTx402Client` wrap an HTTP client and complete the x402 v2 `402 Payment Required` handshake:
  strict decode, local policy, deterministic routing, budget reservation, one signature, one paid
  retry, and a committed ledger entry.
- **Spend policy enforced before any signer call.** Domain allowlist, network allowlist, scheme and
  asset gates, per-request cap, and a rolling one-hour cap, evaluated in the fixed order of
  SPEC §6.3. Money is integer atomic units throughout; a JS `number` or Python `float` amount is
  rejected rather than coerced.
- **An atomic spend ledger** with 120-second reservations, idempotent commit and release, and a
  rolling 3 600 000 ms window over committed spend plus active reservations. `MemorySpendStore`
  ships; `SpendStore` is a public contract you can implement.
- **Deterministic route planning** across every requirement the merchant offered. Balances are
  probed concurrently and deduplicated, then candidates are ordered by a total key cascade —
  viability, open circuit, preference, buyer fee, health score, observed latency, requirement
  index — so identical inputs and health state always select the same route.
- **One health index** shared by both RPC pools: EWMA α=0.20 over a 20-observation window, opening
  at five consecutive failures or ≥50 % of ≥10 samples, 30 s open, one half-open probe, 128-entry
  LRU. A chain-identity mismatch opens immediately rather than being averaged in.
- **Base / EVM adapter.** EIP-3009 `transferWithAuthorization`, with the chain ID proven on the same
  endpoint that serves the balance, on every read, and the full EIP-712 message re-derived and
  checked field by field against the approved plan before the signer is invoked.
- **Solana / SVM adapter.** Canonical associated-token-account derivation, full genesis-hash cluster
  validation, and complete validation of the _serialized_ transaction — wire size, fee payer,
  blockhash, programs, ATAs, mint, authority, amount, decimals — before signing. Token-2022 is
  rejected at planning.
- **A typed error for every failure.** Fifteen codes covering configuration, protocol, policy,
  liquidity, signer, transport, ambiguity, and resource delivery, with `retryable` derived from a
  six-value classification (ADR-011).
- **`tx402 call` CLI** in both languages, at parity: `--dry-run` (which never invokes a signer),
  `--json`, `--max-spend`, `--network`, `--timeout`, and SPEC §11's exit-code table.
- **Redacting diagnostics.** A structured event stream that never carries signatures, keys, or
  authorization payloads — verified by seeding real secrets into every input the request path
  touches and searching the whole serialised stream for each one.
- **An Ed25519-signed release manifest**, compiled into both packages, carrying networks, assets,
  RPC endpoints, and CAIP-2 aliases. Client construction fails if the signature does not verify.
- **73 frozen conformance vectors** in `core-spec/`, executed by both languages against the same
  normalized output, route ordering, error codes, and money rule.

### Security

- The core API accepts signer abstractions only; no public entry point takes a private key string,
  and no CLI flag carries one. Key-loading convenience adapters are isolated in a separate entry
  point that must be imported on purpose, and warn on stderr every time they read the environment.
- Paid retries follow **no** redirect, same-origin included (ADR-014), rather than re-transmitting
  one authorization to a second URL.
- A timeout, reset, or blocked redirect _after_ the signature is transmitted produces
  `AmbiguousPaymentError` with the reservation retained to its TTL — never an automatic retry.
- Importing the core package loads no chain library in either language, asserted in a subprocess.

[Unreleased]: https://github.com/neogeeks/tx402/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/neogeeks/tx402/releases/tag/v0.1.0
