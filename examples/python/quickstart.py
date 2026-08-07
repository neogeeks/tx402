"""tx402 quickstart — a real paid call on Base Sepolia.

    export TX402_DEV_PRIVATE_KEY=0x...        # a dedicated, low-balance test wallet
    export TX402_MERCHANT_URL=https://...     # a merchant that answers 402
    python examples/python/quickstart.py

This is the shortest complete thing that pays for something. It is written to be read top
to bottom rather than to be clever.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from tx402 import AmbiguousPaymentError, Policy, Tx402Client, is_tx402_error
from tx402.errors import Tx402Error

MERCHANT_URL = os.environ.get("TX402_MERCHANT_URL")
PRIVATE_KEY = os.environ.get("TX402_DEV_PRIVATE_KEY")

if not MERCHANT_URL or not PRIVATE_KEY:
    print("Set TX402_MERCHANT_URL and TX402_DEV_PRIVATE_KEY first.", file=sys.stderr)
    raise SystemExit(2)


def log(event: Any) -> None:
    """tx402 never writes to the console itself; it emits a structured stream.

    Every event is redaction-safe by construction — identifiers, hashes, atomic amounts,
    and categories, never a signature, a key, or an authorization payload.
    """
    print("[tx402]", json.dumps(dict(event)), file=sys.stderr)


class Logger:
    debug = staticmethod(lambda _event: None)
    info = staticmethod(log)
    warn = staticmethod(log)
    error = staticmethod(log)


def main() -> int:
    # Imported here rather than at module scope so the import cost lands only on the path
    # that needs it — and so this file still parses on a core-only install.
    from urllib.parse import urlsplit

    from tx402.signers import private_key_to_evm_signer

    # A key in an environment variable is a key any child process can read. Fine for a
    # throwaway testnet wallet, wrong for anything else — use a KMS or hardware signer,
    # which implement the same two-method protocol. See docs/security/keys.
    evm = private_key_to_evm_signer(PRIVATE_KEY)

    # The SDK requires HTTPS for every merchant, and this explicit opt-in is the only way
    # out. The SDK scopes it to localhost/127.0.0.1/::1 itself, so it cannot downgrade a
    # real merchant; it is derived from the URL so copying this file carries nothing with it.
    is_localhost = (urlsplit(MERCHANT_URL).hostname or "") in {
        "localhost",
        "127.0.0.1",
        "::1",
    }

    with Tx402Client(
        evm_signer=evm,
        # Needed only for the quickstart's local test merchant, which speaks plain HTTP.
        allow_insecure_localhost=is_localhost,
        # These are the guardrails, and they run before the signer is reachable.
        # `max_per_hour` is the one that bounds a compromise: if something induces this
        # process to pay repeatedly, the ceiling is this number, not the wallet balance.
        policy=Policy(
            max_per_request="0.10 USDC",
            max_per_hour="1.00 USDC",
            allowed_networks=["eip155:84532"],  # Base Sepolia only
            allowed_domains=[urlsplit(MERCHANT_URL).hostname or "*"],
        ),
        logger=Logger(),
    ) as tx402:
        try:
            response = tx402.get(MERCHANT_URL)
        except Tx402Error as error:
            if not is_tx402_error(error):  # pragma: no cover - defensive
                raise
            print(f"\n{type(error).code}: {error.message}", file=sys.stderr)
            print("details:", json.dumps(dict(error.details), indent=2), file=sys.stderr)

            if isinstance(error, AmbiguousPaymentError):
                # The one case that needs a human. The signature reached the merchant and
                # tx402 could not determine the outcome, so the money may or may not have
                # moved. The budget reservation is deliberately retained rather than
                # released, which is why retrying here can pay twice.
                print(
                    "\nThe payment may have settled. Reconcile before retrying.",
                    file=sys.stderr,
                )
            return 1

        print(f"{response.status_code} {response.reason_phrase}")
        print(response.text)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
