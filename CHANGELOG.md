# Changelog

All notable changes to `tx402` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/) under the policy in [VERSIONING.md](VERSIONING.md).

**The TypeScript and Python packages share this changelog**, because they share a version number
and are released from the same commit. An entry applies to both languages unless it says otherwise.

Breaking changes appear under a `### Breaking` heading — including during 0.x, where SemVer permits
a minor to break you but this project still refuses to let it happen quietly.

## [Unreleased]

## [0.2.0] - 2026-08-12

"Unquestionably safe, phase 1a." 0.2.0 turns the per-process spend guardrails into a **fleet**
control plane: many cooperating agents against one wallet share one authoritative budget, spending
can be frozen, and no merchant can silently redirect a payment. What it does **not** yet claim — and
the [security model](https://docs.tx402.io/security/) says so plainly — is protection of the
spending path against a _compromised_ application; that needs signer mediation and arrives in 0.3.0.

### Added

- **A shared, durable `SpendStore`.** Three reference stores, each behind an optional import off the
  size-gated core path: **Redis** (`tx402/redis` · `tx402.stores.redis`, the `tx402[redis]` extra,
  sync and async), a **Cloudflare Durable Object** (`tx402/durable-object`, SQLite-backed,
  id-per-scope or single-coordinator), and a **capability gateway** (`tx402/gateway` ·
  `tx402.stores.gateway`) that fronts either backend and is the durable data/admin boundary. A fleet
  sharing one store shares one per-hour rate, one cumulative ceiling, one freeze switch, and one set
  of recipient pins. See [the shared-store runbook](https://docs.tx402.io/operations/shared-store/).
- **A cumulative cap.** `policy.maxTotal` / `Policy(max_total=…)` bounds _lifetime_ spend against a
  scope, not just the rolling hour, and never resets automatically. An operator may administer the
  authoritative caps in the store so a drifted worker cannot widen them (§4.3).
- **A kill switch.** An operator can `freeze` a merchant scope — or the whole store with `"*"` on a
  backend that supports atomic global freeze — and every subsequent reserve is denied before a
  signer is reached. See [the kill-switch runbook](https://docs.tx402.io/operations/kill-switch/).
- **Recipient pinning.** `recipientPolicy` pins a merchant's payout address (`allowlist` or trust-on
  first-use), so a merchant that changes its recipient mid-conversation is refused rather than paid.
  A legitimate change is an operator action — see
  [recipient rotation](https://docs.tx402.io/operations/recipient-rotation/).
- **Durable ambiguous-payment accounting.** A maybe-settled ("exposed") payment is fenced durably
  _before_ transmission and counts against both caps until an operator reconciles it with
  `listExposed` → `resolveExposed`; it never escapes on a TTL. See
  [exposed reconciliation](https://docs.tx402.io/operations/exposed-reconciliation/).
- **Five operator CLI verbs** — `freeze`, `unfreeze`, `budget`, `pins`, `rotate-recipient` — that
  govern a shared store from the shell via `TX402_SPEND_STORE` and a data/admin credential split, at
  byte-for-byte TypeScript↔Python parity.
- **Four request-path events** — `payment.exposed`, `spend.frozen`, `recipient.pinned`,
  `recipient.rejected` — extending the closed `EVENT_NAMES` set, each redaction-safe.
- **Additive contract surface** that needs no code change: `capKind: "cumulative"` on
  `BudgetExceededError`, the new `BudgetState` counters, `AsyncSpendStore` / `AsyncRecipientPinStore`,
  and `listExposed`.
- **Eighty-eight** frozen conformance vectors (from seventy-three) and new vector kinds
  (`spend-freeze.behavior`, `recipient-pin.behavior`, extended `spend-ledger.behavior`), executed
  identically by both languages and, for the durable stores, behind the gateway in CI.

### Breaking

Every entry here is a change a custom `SpendStore` or a direct caller must follow; a single-process
integration that keeps the default `MemorySpendStore` and sets neither `maxTotal` nor
`recipientPolicy` is unaffected.

- **Two new error codes** — `TX402_SPEND_FROZEN` (`SpendScopeFrozenError`) and
  `TX402_RECIPIENT_UNPINNED` (`RecipientUnpinnedError`), taxonomy **15 → 17**, both mapping to exit
  `3`. Adding a code is a break because callers match the taxonomy exhaustively; the exit-number set
  is unchanged.
- **`SpendStore` data-plane contract v2.** A store passed to the client must now implement `expose`,
  `listExposed`, `isFrozen`, and a required `capabilities` property (`{ atomicGlobalFreeze }`);
  `reserve` may throw `SpendScopeFrozenError` / `RecipientUnpinnedError`; `assert_spend_store` /
  `checkSpendStore` enforce the new members. Freeze/unfreeze are admin-plane and not required of the
  data-plane object.
- **`reserve` returns a `ReserveSpendResult`, not a bare `SpendReservation`.** Read
  `result.reservation` (and `result.recipientPinEstablished`).
- **Lifecycle operations take a `ReservationRef`, not a bare id.** `release`, `expose`, and admin
  `resolveExposed` accept `{ reservationId, policyScope, assetId }`, and `CommitSpendInput` gains
  `policyScope` / `assetId`. An in-process caller passes the `SpendReservation` it already holds.
- **Backend-authoritative time.** Durable stores window on the _store's_ clock, so
  `BudgetQuery.nowEpochMs` is advisory for them — querying a past instant works only on
  `MemorySpendStore`. This reverses v0.1's caller-supplied time and is what stops a skewed caller
  from widening its cap.
- **`commit(expired)` is now refused** (`expired-cannot-commit`) where v0.1 permitted it — required
  for cumulative-cap correctness.
- **`AsyncTx402Client.get_budget_state(...)` is now `async def`.** Callers of the async client must
  `await` it; the sync client is unchanged.
- **The fixed policy evaluation order gains a recipient step**, observable only when
  `recipientPolicy.mode` is not `"off"`.
- **Python `payTo` is now bounded at ≤ 128 characters**, matching the TypeScript validation.

### Security

- **A data/admin-state boundary.** The fleet controls above are set through an admin credential the
  agents do not hold; a data-plane worker can reserve and read but cannot freeze, re-pin, or raise a
  limit. Enforced durably by the gateway, and approximately by a raw-Redis key-pattern ACL or the
  Durable Object's in-object admin-token verification. It protects **admin state**, not the spending
  path against a compromised app (0.3.0) — stated, not implied.
- **The exposure fence is durable and pre-transmission.** A signature is transmitted only after the
  reservation is fenced, and a fence-write failure aborts the transmission with nothing sent, so an
  ambiguous outcome can never silently free budget.
- **The new events and errors are redaction-safe by construction**, proven by the same
  seed-a-secret-and-search test the request path already passes.

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
- **Seventy-three frozen conformance vectors** in `core-spec/`, executed by both languages against the same
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

[Unreleased]: https://github.com/neogeeks/tx402/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/neogeeks/tx402/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/neogeeks/tx402/releases/tag/v0.1.0
