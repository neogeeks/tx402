"""Regressions for the S20 fresh-eyes UX pass (§11.3), open items O77 and O79.

The twin of ``packages/tx402/test/ux-regressions-s20.test.ts``. Both were run against
``ee587df`` first to confirm they failed there; a regression that passes before the fix is
not evidence.

Only the behavioural half lives here. O78's example sources and O80/O81's documentation
pages are single shared files, and asserting them from two suites would pin them twice
without pinning anything more.

Python's version of the defect was the worse of the two, because ``except Exception``
swallows ``ModuleNotFoundError`` as readily as it swallows a validation error: a missing
``evm`` extra was reported as a malformed ``TX402_DEV_PRIVATE_KEY``, fatally, on the
quickstart's own Solana row — a path that needs no EVM anything.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from tests.test_cli import DEV_KEY, Harness
from tests.test_payment_paths import (
    BASE,
    URL,
    Merchant,
    challenge,
    evm_requirement,
    evm_rpc,
    svm_rpc,
)
from tx402.cli import DEV_KEY_ENV, EXIT_CODES, run_cli
from tx402.client import Tx402Client

#: A structurally valid keypair. The point of O77 is that a *valid* key was rejected.
SOLANA_KEYPAIR = "[" + ",".join(str(index % 256) for index in range(64)) + "]"

BOTH_KEYS = {
    DEV_KEY_ENV["evm"]: DEV_KEY,
    DEV_KEY_ENV["solana"]: SOLANA_KEYPAIR,
}


def env_client(merchant: Any) -> Any:
    """Wires transports but leaves the CLI's own resolved signers in place."""

    def create(**config: Any) -> Tx402Client:
        return Tx402Client(
            **config,
            transport=httpx.MockTransport(merchant),
            evm_rpc_transport=evm_rpc(),
            solana_rpc_transport=svm_rpc(),
        )

    return create


@pytest.fixture
def merchant() -> Merchant:
    return Merchant(offers=[challenge(evm_requirement())])


class TestO77MissingExtraIsNotAMalformedKey:
    def test_does_not_fail_a_request_for_a_chain_it_never_needed(
        self, merchant: Merchant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # `from tx402.signers import keypair_to_solana_signer` runs inside the loader on
        # every call, so patching the attribute is the same seam a missing `svm` extra
        # takes: the name resolution raises ImportError.
        def missing_extra(_keypair: str) -> Any:
            raise ModuleNotFoundError("No module named 'solders'")

        monkeypatch.setattr(
            "tx402.signers.keypair_to_solana_signer", missing_extra, raising=True
        )

        harness = Harness(
            ["call", URL, "--max-spend", "0.10 USDC", "--network", BASE, "--dry-run"],
            env=BOTH_KEYS,
            create_client=env_client(merchant),
        )
        assert run_cli(harness) == EXIT_CODES["success"]

        stderr = harness.stderr_text
        assert "is not installed, so that signer was not loaded" in stderr
        assert 'pip install "tx402[svm]"' in stderr
        # And emphatically not as a bad key, which is what sent the reporter off to
        # regenerate a keypair that was already valid.
        assert "is not a JSON array of 64 Solana keypair bytes" not in stderr
        assert "would pay" in stderr

    def test_still_reports_a_genuinely_malformed_key_as_such(
        self, merchant: Merchant
    ) -> None:
        # Collapsing the two failures in the safe direction would be as wrong as
        # collapsing them in the unsafe one.
        harness = Harness(
            ["call", URL, "--max-spend", "0.10 USDC", "--network", BASE],
            env={DEV_KEY_ENV["evm"]: "0xnothex"},
            create_client=env_client(merchant),
        )
        assert run_cli(harness) == EXIT_CODES["usage"]
        assert (
            f"{DEV_KEY_ENV['evm']} is not a 0x-prefixed 32-byte hex private key"
            in harness.stderr_text
        )


class TestO79MissingExtraNamesTheInstall:
    def test_reports_the_extra_to_install_rather_than_an_import_error(
        self, merchant: Merchant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def missing_extra(_key: str) -> Any:
            raise ImportError("No module named 'x402.evm'")

        monkeypatch.setattr(
            "tx402.signers.private_key_to_evm_signer", missing_extra, raising=True
        )

        harness = Harness(
            ["call", URL, "--max-spend", "0.10 USDC", "--network", BASE, "--dry-run"],
            env={DEV_KEY_ENV["evm"]: DEV_KEY},
            create_client=env_client(merchant),
        )
        # The documented exit 5, not an unhandled traceback.
        assert run_cli(harness) == EXIT_CODES["protocol"]

        stderr = harness.stderr_text
        assert 'pip install "tx402[evm]"' in stderr
        assert "ModuleNotFoundError" not in stderr
        assert "Traceback" not in stderr
        assert harness.stdout_text == ""
