# tx402

**Resilient x402 buyer SDK for Python.** Deterministic multi-chain payment routing, local spend
guardrails, and a drop-in `httpx` wrapper for autonomous agents.

Feature-complete and at behavioural parity with the TypeScript SDK — both execute the same 73
language-neutral conformance fixtures.

## What it does

An AI agent running a 50-step workflow cannot afford to have step 45 die because one payment
facilitator rate-limited it or the merchant wanted USDC on a chain the agent wasn't configured
for. `tx402` wraps a normal HTTP client and handles the `402 Payment Required` handshake:

```python
from tx402 import Policy, Tx402Client

client = Tx402Client(
    evm_signer=evm_signer,
    solana_signer=solana_signer,
    policy=Policy(
        max_per_request="0.50 USDC",
        max_per_hour="10.00 USDC",
        allowed_networks=["eip155:8453", "solana:mainnet"],
    ),
)

response = client.post(url, json={"prompt": "Hello"})
```

Under the hood, on a `402`, it decodes the challenge strictly, enforces your spend policy
**before any key is touched**, deterministically ranks every route the merchant offered —
scored by balance, expected buyer fee, and local endpoint health — verifies the chain
identity on the RPC endpoint that serves the balance, reserves the spend atomically, asks
your signer for exactly one bounded authorization with a fresh nonce, and retries once with
it. A merchant that re-challenges gets a freshly parsed challenge and a new signature, up to
`max_paid_attempts`.

Both `Tx402Client` and `AsyncTx402Client` are provided, and both support Base (EIP-3009) and
Solana (SPL exact transfer).

## Design commitments

- **Non-custodial.** The core API accepts signer abstractions, never raw private key strings.
  Private keys never leave your process, and are never logged or transmitted.
- **Policy before signature.** Budget caps, domain allowlists, and network allowlists are evaluated
  and the spend is reserved *before* a signer is ever invoked.
- **Integer money.** All amounts are integer atomic units. `float` money inputs are rejected, not
  coerced — a cap that rounds is not a cap.
- **No backend.** No tx402-operated service, no telemetry, no phone-home. The only network calls
  are to the merchant you asked for and the RPC endpoints you configured.
- **Same-chain only.** It pays on a network the merchant offered and you can sign for. It will not
  bridge or swap behind your back; if you can't pay, you get a typed `InsufficientLiquidityError`.
- **The buyer never talks to a facilitator.** `/verify` and `/settle` are the merchant's
  calls, not yours.

## Sharing one budget across processes

`Policy(max_per_hour=…)` is enforced against a `SpendStore`. The default is in-memory and
therefore per-process; a fleet of agents that must share one hourly cap supplies its own:

```python
from tx402 import SpendStore, Tx402Client, check_spend_store, normalize_policy_host

class RedisSpendStore:      # structural — nothing to subclass or import
    kind = "redis"
    def reserve(self, *, reservation_id, request_id, policy_scope, request_fingerprint,
                asset_id, amount_atomic, max_per_hour_atomic, now_epoch_ms): ...
    def commit(self, *, reservation_id, committed_at_epoch_ms, settlement_id=None): ...
    def release(self, *, reservation_id, now_epoch_ms): ...
    def get_budget_state(self, *, policy_scope, asset_id, now_epoch_ms): ...

check_spend_store(lambda: RedisSpendStore())   # shipped conformance suite; raises on a violation
client = Tx402Client(spend_store=RedisSpendStore(), ...)
```

`policy_scope` is the **normalized merchant host** — `normalize_policy_host(url)` produces
it — so two processes calling one merchant share one cap. `check_spend_store` runs the whole
contract, including twenty concurrent reservations against a five-unit cap, because the rule
an adapter is most likely to break is that `reserve` must be atomic. See
`tx402.ledger.SpendStore` for the full contract.

## Install

```bash
pip install tx402            # core: protocol codec + HTTP transport
pip install "tx402[evm]"     # + Base / EVM signing
pip install "tx402[svm]"     # + Solana signing
pip install "tx402[all]"     # everything
```

Requires Python 3.10+.

## Parity with the TypeScript SDK

The TypeScript SDK ([`tx402` on npm](https://www.npmjs.com/package/tx402)) is the reference
implementation. Both are validated against the same language-neutral conformance fixtures, and a
behavioural change lands in both languages together or not at all.

## License

Apache-2.0
