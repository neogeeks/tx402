"""
tx402 0.2.0 — a fleet against one shared budget.

    pip install "tx402[redis]"
    redis-server --appendonly yes            # any Redis 7.0+, or an Upstash rediss:// endpoint
    export TX402_SPEND_STORE=redis://localhost:6379/15
    python examples/python/fleet.py

This is the 0.2.0 story in one file: many cooperating agents share one authoritative budget in a
durable store, an operator administers caps and pins that a drifted worker cannot relax, and the
kill switch stops spending on command. It talks to the store directly so it runs without a merchant;
the CLI equivalents are `tx402 budget` / `tx402 freeze` / `tx402 rotate-recipient`.

It writes only under a demo namespace and deletes those keys on the way out, so it is safe to re-run.
"""

import os
import time

import redis

from tx402 import Policy, RecipientPolicy, Tx402Client, is_tx402_error
from tx402.ledger import BudgetLimits
from tx402.stores.redis import RedisSpendStore

REDIS_URL = os.environ.get("TX402_SPEND_STORE", "redis://localhost:6379/15")
NAMESPACE = "tx402-fleet-example"
SCOPE = "api.merchant.example"
NETWORK = "eip155:8453"
ASSET = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # USDC on Base


def now() -> int:
    # The durable store windows on its own clock, so a timestamp passed in here is only advisory.
    return int(time.time() * 1000)


def main() -> None:
    connection = redis.Redis.from_url(REDIS_URL)

    # Two credentials, one boundary. The agents get the DATA store (admin=False): it can reserve and
    # read but cannot freeze, re-pin, or raise a limit. An operator holds the ADMIN store.
    data = RedisSpendStore(connection, namespace=NAMESPACE, admin=False)
    admin = RedisSpendStore(connection, namespace=NAMESPACE, admin=True)

    try:
        # --- Operator: administer caps and a recipient allowlist, in the store ---------------------
        # A cumulative ceiling ($50) and an hourly rate ($1) that a worker cannot widen by asking.
        admin.set_budget_limits(
            SCOPE, ASSET, BudgetLimits(max_per_hour_atomic="1000000", max_total_atomic="50000000"), now()
        )
        # Pin the merchant's payout address. A payment to any other address will be refused.
        admin.set_recipient_pins(SCOPE, NETWORK, ("0x1111111111111111111111111111111111111111",), now())

        # --- Any agent: read the one shared budget ------------------------------------------------
        state = data.get_budget_state(policy_scope=SCOPE, asset_id=ASSET, now_epoch_ms=now())
        print("shared budget for", SCOPE)
        print("  per-hour limit :", state.per_hour_limit_atomic, "atomic  (administered)")
        print("  cumulative cap :", state.cumulative_limit_atomic, "atomic  (administered)")
        print("  committed      :", state.committed_atomic)
        print("  frozen         :", state.frozen)

        # --- The boundary in action: a data credential cannot administer -------------------------
        try:
            data.freeze(SCOPE, now())
            print("\n!! a data-plane store froze the scope — the boundary is broken")
        except Exception as error:  # noqa: BLE001 — we want to show exactly which typed error it is
            if is_tx402_error(error):
                print("\ndata-plane freeze refused:", error.code, "/", error.details.get("reason"))
            else:
                raise

        # --- Operator: the kill switch ------------------------------------------------------------
        admin.freeze(SCOPE, now())
        print("after admin freeze, is_frozen =", data.is_frozen(scope=SCOPE))  # -> True
        admin.unfreeze(SCOPE, now())
        print("after admin unfreeze, is_frozen =", data.is_frozen(scope=SCOPE))  # -> False

        # --- The client the agents actually run ---------------------------------------------------
        # It reserves against the shared `data` store. `max_total` is the caller's ceiling; the
        # store's administered cap still binds via min(). `recipient_policy` mirrors the pin.
        Tx402Client(
            spend_store=data,
            policy=Policy(max_per_request="0.10 USDC", max_per_hour="1.00 USDC", max_total="50.00 USDC"),
            recipient_policy=RecipientPolicy(
                mode="allowlist",
                allow=[{"host": SCOPE, "network": NETWORK, "recipients": ["0x1111111111111111111111111111111111111111"]}],
            ),
        )
        print("\nclient constructed against the shared store — set TX402_MERCHANT_URL and add a")
        print("signer to make a real paid call (see quickstart.py).")
    finally:
        # Best-effort cleanup so the example is idempotent. It only touches this demo namespace.
        keys = list(connection.scan_iter(match=f"*{NAMESPACE}*"))
        if keys:
            connection.delete(*keys)


if __name__ == "__main__":
    main()
