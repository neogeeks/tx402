# tx402

**The spend-governance layer for x402, in Python.** Spend caps and budgets enforced before any
key is signed, deterministic multi-chain routing, and a drop-in `httpx` wrapper for autonomous agents.

Feature-complete and at behavioural parity with the TypeScript SDK — both execute the same 88
language-neutral conformance fixtures.

## What it does

An AI agent is a loop with a private key. Making one payment is easy — the hard part is trusting the
ten-thousandth, unattended: a per-request cap says nothing about the total, and a budget checked
_after_ you've signed is a receipt, not a control. `tx402` wraps a normal HTTP client and handles the
`402 Payment Required` handshake, with your spend policy as the first thing it enforces:

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
therefore per-process; a fleet of agents that must share one hourly cap points at a durable one.
The Redis adapter ships in the box (`pip install "tx402[redis]"`):

```python
from redis import Redis
from tx402 import Tx402Client
from tx402.stores.redis import RedisSpendStore

store = RedisSpendStore(Redis.from_url("redis://localhost:6379/0"))
client = Tx402Client(spend_store=store, ...)   # every agent shares one authoritative cap
```

A gateway-backed store (`tx402.stores.gateway`, over an HTTP wire protocol) and a Cloudflare
Durable Object are the other reference backends; [`examples/python/fleet.py`](https://github.com/neogeeks/tx402/blob/main/examples/python/fleet.py)
is a runnable end-to-end fleet that shares one Redis budget across processes.

**Writing your own?** Implement the whole v2 `SpendStore` contract — a `kind` string, a
`capabilities` with `atomic_global_freeze`, `reserve`, the ref-based `commit` / `release` /
`expose` (each takes a `ReservationRef`, not a bare id), `get_budget_state`, `list_exposed`, and
`is_frozen` — then verify it with the shipped conformance suite before you construct a client
around it:

```python
from tx402.spend_store_contract import check_spend_store

check_spend_store(
    lambda: MyStore()
)  # raises SpendStoreContractError on the first violation
```

`check_spend_store` runs the whole contract, including twenty concurrent reservations against a
five-unit cap, because the rule an adapter is most likely to break is that `reserve` must be
atomic. `policy_scope` is the **normalized merchant host** (`normalize_policy_host(url)`), so two
processes calling one merchant share one cap. See `tx402.ledger.SpendStore` for the full contract.

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
