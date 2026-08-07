"""Inspect a merchant's terms without paying, and without a key.

    export TX402_MERCHANT_URL=https://...
    python examples/python/dry_run.py

``client.inspect()`` performs the request, decodes and strictly validates the merchant's
``PAYMENT-REQUIRED`` challenge, and stops. It configures no signer, contacts no chain, and
cannot spend anything — so it is safe to run in a loop, in CI, or from an agent that should
be able to find out what something costs without being able to buy it.

**``inspect()`` and ``plan()`` are different questions, and only one of them is keyless.**
``inspect()`` answers "what is this merchant asking for?" — a property of the challenge
alone. ``plan()`` answers "what would I actually pay, and by which route?", which means
ranking the offered routes, which means reading your address and balance on each one. A
route it cannot price is a route it cannot rank, so ``plan()`` — and the CLI's
``--dry-run``, which is the same call — require a configured signer. Neither ever produces
a signature.
"""

from __future__ import annotations

import os
import sys

from tx402 import Policy, Tx402Client
from tx402.errors import Tx402Error

MERCHANT_URL = os.environ.get("TX402_MERCHANT_URL")
if not MERCHANT_URL:
    print("Set TX402_MERCHANT_URL first.", file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    from urllib.parse import urlsplit

    # The SDK requires HTTPS for every merchant; this opt-in is scoped to localhost by the
    # SDK itself and derived from the URL, so copying this file carries no relaxation.
    is_localhost = (urlsplit(MERCHANT_URL).hostname or "") in {
        "localhost",
        "127.0.0.1",
        "::1",
    }

    # No signers configured at all, and none needed: `inspect()` never reaches a chain.
    with Tx402Client(
        allow_insecure_localhost=is_localhost,
        policy=Policy(
            max_per_request="1.00 USDC",
            # Testnets are never allowed by default: a silent fall back from production
            # to a testnet is worse than a refusal.
            allowed_networks=["eip155:84532", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"],
        ),
    ) as tx402:
        try:
            inspection = tx402.inspect("GET", MERCHANT_URL)
        except Tx402Error as error:
            # Inspection can still fail: an unreachable merchant, or a challenge that does
            # not decode. Both are worth seeing before you try to pay.
            print(f"{type(error).code}: {error.message}", file=sys.stderr)
            return 1

        if inspection.payment_required is None:
            print(
                "No payment required — the resource answered "
                f"{inspection.response.status_code}."
            )
            return 0

        print(f"request      {inspection.request_id}")
        print(f"requirements {len(inspection.payment_required['requirements'])}")
        print(f"header hash  {inspection.payment_required['headerHash']}\n")

        print("What the merchant accepts:")
        for requirement in inspection.payment_required["requirements"]:
            print(
                f"  [{requirement['index']}] {requirement['amountAtomic']} atomic  "
                f"{requirement['scheme']} on {requirement['network']}"
            )

        print("\nNothing was signed, no budget was reserved, and no chain was contacted.")
        print("To see how tx402 would rank these routes, configure a signer and use")
        print("`client.plan()` — or `tx402 call <url> --dry-run` from the CLI.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
