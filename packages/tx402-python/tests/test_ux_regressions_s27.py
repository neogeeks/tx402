"""Regressions for the fifth fresh-eyes UX pass (§11.3), open item O93.

Run against ``290d69c`` first and observed to fail there.

O93 was found in the TypeScript CLI and reported as byte-identical in Python — the two
renderers had drifted together, not apart, because the same structure was written twice.
That makes it exactly the kind of finding that gets half-fixed: repair the language it was
demonstrated in, and leave the other one carrying it.

Two renderers could each print the same sentence. An advisory keyed on the error code
emitted "the payment may have settled — do not retry without checking the merchant", and
the settlement block's own header emitted "the payment may have settled" immediately
after. So an ambiguous payment said it twice — and ``TX402_REDIRECT_BLOCKED``, the *other*
exit-8 code and equally dangerous, said it once **without** the instruction, because the
advisory was keyed on a code rather than on the disposition.

Both now derive from ``context.paid``, the field that carries "money may have moved".
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from tests.test_payment_paths import (
    URL,
    Merchant,
    challenge,
    evm_requirement,
    evm_rpc,
    settlement,
    svm_rpc,
)
from tx402.cli import EXIT_CODES, CliIo, run_cli
from tx402.client import Tx402Client

DEV_KEY = "0xa11ce00000000000000000000000000000000000000000000000000000000001"


class _Signer:
    kind = "evm"

    def get_address(self) -> str:
        return "0xaad1566216D2447B530E04945dfEefD04C84967B"

    def sign_typed_data(self, request: Any) -> bytes:
        return b"s" * 65


class _Harness(CliIo):
    def __init__(self, argv: list[str], **overrides: Any) -> None:
        self.out: list[str] = []
        self.err: list[str] = []

        def no_filesystem(path: str) -> str:
            raise OSError("no filesystem in this test")

        defaults: dict[str, Any] = {
            "argv": argv,
            "env": {"TX402_DEV_PRIVATE_KEY": DEV_KEY},
            "stdout": self.out.append,
            "stderr": self.err.append,
            "read_file": no_filesystem,
        }
        defaults.update(overrides)
        super().__init__(**defaults)

    @property
    def stderr_text(self) -> str:
        return "".join(self.err)


def _run(merchant: Merchant) -> tuple[int, str]:
    def create(**config: Any) -> Tx402Client:
        config.pop("evm_signer", None)
        return Tx402Client(
            **config,
            evm_signer=_Signer(),
            transport=httpx.MockTransport(merchant),
            evm_rpc_transport=evm_rpc(),
            solana_rpc_transport=svm_rpc(),
        )

    harness = _Harness(
        ["call", URL, "--max-spend", "0.10 USDC", "--network", "eip155:8453"],
        create_client=create,
    )
    code = run_cli(harness)
    return code, harness.stderr_text


def test_an_ambiguous_payment_says_may_have_settled_exactly_once() -> None:
    """The duplicate. Two renderers, one sentence, printed back to back."""
    merchant = Merchant(
        offers=[challenge(evm_requirement())],
        paid_statuses=[503],
    )
    code, err = _run(merchant)
    assert code == EXIT_CODES["ambiguous_payment"]
    assert err.count("the payment may have settled") == 1


def test_a_blocked_cross_origin_redirect_is_told_not_to_retry() -> None:
    """The half that mattered.

    ``TX402_REDIRECT_BLOCKED`` is reachable only after a signature was transmitted, and
    the error reference groups it with ``TX402_PAYMENT_AMBIGUOUS`` as identically
    dangerous — but it never printed the "do not retry" instruction, only the settlement
    block's header. The whole reason exit 8 has its own code is that a human stops.
    """
    merchant = Merchant(
        offers=[challenge(evm_requirement())],
        paid_statuses=[307],
        paid_headers={"location": "https://elsewhere.example/x"},
    )
    code, err = _run(merchant)
    assert code == EXIT_CODES["ambiguous_payment"]
    assert "do not retry without checking the merchant" in err
    assert err.count("the payment may have settled") == 1


def test_a_settled_payment_is_still_worded_differently() -> None:
    """The do-not-regress half.

    Exit 9 with money actually moved must not be collapsed into the ambiguous wording: the
    correct action differs, and that difference is the entire point of the two codes.
    """
    merchant = Merchant(
        offers=[challenge(evm_requirement())],
        paid_statuses=[403],
        paid_headers={"PAYMENT-RESPONSE": settlement()},
    )
    code, err = _run(merchant)
    assert code == EXIT_CODES["resource_failure"]
    assert "the payment settled — the resource is what failed" in err
    assert "may have settled" not in err


@pytest.mark.parametrize("status", [503, 307])
def test_the_advisory_survives_without_a_settlement_object(status: int) -> None:
    """Keying on ``paid`` rather than on the error code must not lose the line entirely.

    The advisory has to print even when no settlement object could be built, which is the
    case the old code-keyed branch happened to cover and a naive rewrite would drop.
    """
    merchant = Merchant(
        offers=[challenge(evm_requirement())],
        paid_statuses=[status],
        paid_headers=({"location": "https://elsewhere.example/x"} if status == 307 else {}),
    )
    _code, err = _run(merchant)
    assert "do not retry without checking the merchant" in err
