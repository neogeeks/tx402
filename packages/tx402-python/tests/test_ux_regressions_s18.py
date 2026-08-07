"""Regressions for the S18 fresh-eyes UX pass (§11.3), open items O72 to O76.

The twin of ``packages/tx402/test/ux-regressions-s18.test.ts``. Both were run against
``7376245`` first to confirm they failed there; a regression that passes before the fix is
not evidence.

The documentation-fixture assertions (O72/O73, O76) live only in the TypeScript twin — the
page they read is one shared file, and asserting it from two suites would pin it twice
without pinning anything more. What is genuinely Python here is O74 and O75: both CLIs must
emit the same ``--json`` document and the same stderr, and the only way that stays true is
if both suites ask the same questions.
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
    settlement,
    svm_rpc,
)
from tx402.cli import DEV_KEY_ENV, EXIT_CODES, run_cli
from tx402.client import Tx402Client
from tx402.signers import private_key_to_evm_signer

#: The environment a real shell hands the CLI. Using this rather than injecting a signer is
#: the point: the payer address the settlement report carries comes from the signers the CLI
#: resolves for itself, so an injected signer would assert the reporting path against a
#: configuration no real run ever has.
DEV_ENV = {DEV_KEY_ENV["evm"]: DEV_KEY}

EXPECTED_PAYER = private_key_to_evm_signer(DEV_KEY).get_address()


def env_client(merchant: Any, **overrides: Any) -> Any:
    """Wires transports but leaves the CLI's own resolved signers in place."""

    def create(**config: Any) -> Tx402Client:
        wiring: dict[str, Any] = {
            "transport": httpx.MockTransport(merchant),
            "evm_rpc_transport": evm_rpc(),
            "solana_rpc_transport": svm_rpc(),
        }
        wiring.update(overrides)
        return Tx402Client(**config, **wiring)

    return create


@pytest.fixture
def merchant() -> Merchant:
    return Merchant(offers=[challenge(evm_requirement())])


class TestO74SettlementFactsReachTheOperator:
    def test_reports_the_settlement_identifier_and_payer_on_a_delivered_payment(
        self, merchant: Merchant
    ) -> None:
        import json

        harness = Harness(
            ["call", URL, "--max-spend", "0.10 USDC", "--json"],
            env=DEV_ENV,
            create_client=env_client(merchant),
        )
        assert run_cli(harness) == EXIT_CODES["success"]

        document = json.loads(harness.stdout_text)
        assert document["settlement"]["status"] == "committed"
        # Unhashed: a `sha256:…` cannot be looked up on a block explorer (ADR-019).
        assert document["settlement"]["transaction"] == "0xtx"
        assert not document["settlement"]["transaction"].startswith("sha256:")
        assert document["settlement"]["payer"] == EXPECTED_PAYER

    def test_reports_settlement_on_exit_nine_where_money_moved(self) -> None:
        import json

        # 403 carrying a successful PAYMENT-RESPONSE: settlement evidence outranks the
        # status line (ADR-016), so the money moved and the resource did not arrive.
        merchant = Merchant(
            offers=[challenge(evm_requirement())],
            paid_statuses=[403],
            paid_headers={"PAYMENT-RESPONSE": settlement()},
        )
        harness = Harness(
            ["call", URL, "--max-spend", "0.10 USDC", "--json"],
            env=DEV_ENV,
            create_client=env_client(merchant),
        )
        assert run_cli(harness) == EXIT_CODES["resource_failure"]

        document = json.loads(harness.stdout_text)
        assert document["settlement"]["status"] == "committed"
        assert document["settlement"]["transaction"] == "0xtx"

    def test_prints_the_settlement_facts_on_stderr_too(self) -> None:
        # Exit 9's advice is "do not retry". Requiring `--json` to obtain the identifier
        # would mean re-running the payment to find out what the payment was.
        merchant = Merchant(
            offers=[challenge(evm_requirement())],
            paid_statuses=[403],
            paid_headers={"PAYMENT-RESPONSE": settlement()},
        )
        harness = Harness(
            ["call", URL, "--max-spend", "0.10 USDC"],
            env=DEV_ENV,
            create_client=env_client(merchant),
        )
        assert run_cli(harness) == EXIT_CODES["resource_failure"]

        assert "payer" in harness.stderr_text
        assert "settlement" in harness.stderr_text
        assert EXPECTED_PAYER in harness.stderr_text
        assert "0xtx" in harness.stderr_text
        # The SPEC §11 split holds: diagnostics never reach stdout.
        assert harness.stdout_text == ""

    def test_reports_null_rather_than_inventing_a_settlement(self) -> None:
        import json

        # A merchant that never charges must not produce a settlement object, or the field
        # becomes meaningless the first time someone trusts it.
        def never_charges(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"free")

        harness = Harness(
            ["call", URL, "--max-spend", "0.10 USDC", "--json"],
            env=DEV_ENV,
            create_client=env_client(never_charges),
        )
        assert run_cli(harness) == EXIT_CODES["success"]
        assert json.loads(harness.stdout_text)["settlement"] is None

    def test_keeps_the_event_streams_settlement_identifier_hashed(
        self, merchant: Merchant
    ) -> None:
        # The other half of ADR-019: exposing the raw value on the buyer's own stdout must
        # not relax the SPEC §10 rule for events, which reach a log aggregator.
        events: list[dict[str, Any]] = []

        class Recorder:
            def debug(self, event: Any) -> None:
                events.append(dict(event))

            info = debug
            warn = debug
            error = debug

        with Tx402Client(
            evm_signer=private_key_to_evm_signer(DEV_KEY),
            transport=httpx.MockTransport(merchant),
            evm_rpc_transport=evm_rpc(),
            solana_rpc_transport=svm_rpc(),
            logger=Recorder(),
        ) as client:
            client.get(URL)

        completed = next(e for e in events if e.get("event") == "payment.completed")
        assert completed["settlementIdHash"].startswith("sha256:")
        assert "settlementId" not in completed


class TestO75APrintedRemedyTheOperatorCanFollow:
    def test_prints_offered_networks_on_stderr_without_json(
        self, merchant: Merchant
    ) -> None:
        # The most likely first error. The message says to copy a value out of
        # `offeredNetworks`, and that key previously existed only under `--json` — so the
        # default run printed advice referring to something it never showed.
        harness = Harness(
            ["call", URL, "--max-spend", "0.10 USDC", "--network", "eip155:84532"],
            env=DEV_ENV,
            create_client=env_client(merchant),
        )
        assert run_cli(harness) == EXIT_CODES["protocol"]

        assert "TX402_SCHEME_UNSUPPORTED" in harness.stderr_text
        assert "offeredNetworks" in harness.stderr_text
        assert BASE in harness.stderr_text
        # The remedy is a diagnostic and belongs on stderr, or `tx402 call … > out.json`
        # stops producing a usable file.
        assert harness.stdout_text == ""
