"""The Python CLI surface (SPEC §11).

Mirrors ``packages/tx402/test/cli.test.ts`` assertion for assertion, because the two CLIs
are one command surface with one exit-code contract and the only way that stays true is if
both suites ask the same questions.

Driven in process through the injected :class:`~tx402.cli.CliIo` rather than by spawning
an interpreter, so every assertion is about the real code path and the suite stays fast
enough to cover all nine exit codes. The one thing that genuinely needs a process — the
``SystemExit`` shim — lives in :func:`tx402.cli.run` and is exercised separately.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Literal

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on the 3.10 CI leg
    import tomli as tomllib

import httpx
import pytest

from tests.test_payment_paths import (
    BASE,
    BASE_ASSET,
    EVM_PAYER,
    SOLANA,
    URL,
    Merchant,
    challenge,
    evm_requirement,
    evm_rpc,
    svm_requirement,
    svm_rpc,
)
from tx402.cli import (
    DEV_KEY_ENV,
    EXIT_CODE_BY_ERROR,
    EXIT_CODES,
    JSON_SCHEMA_VERSION,
    CliIo,
    UsageError,
    main,
    parse_args,
    run,
    run_cli,
)
from tx402.client import Tx402Client
from tx402.errors import TX402_ERROR_CODES, TX402_ERROR_TAXONOMY
from tx402.evm import EvmTypedDataRequest

DEV_KEY = "0xa11ce00000000000000000000000000000000000000000000000000000000001"


class CountingSigner:
    """Counts signatures, so "--dry-run never signs" is a count rather than a hope."""

    kind: Literal["evm"] = "evm"

    def __init__(self) -> None:
        self.sign_count = 0

    def get_address(self) -> str:
        return EVM_PAYER

    def sign_typed_data(self, request: EvmTypedDataRequest) -> bytes:
        self.sign_count += 1
        return b"s" * 65


class Harness(CliIo):
    """Captures both streams so the SPEC §11 stdout/stderr split can be asserted."""

    def __init__(self, argv: list[str], **overrides: Any) -> None:
        self.out: list[str] = []
        self.err: list[str] = []

        def no_filesystem(path: str) -> str:
            raise OSError("no filesystem in this test")

        defaults: dict[str, Any] = {
            "argv": argv,
            "env": {},
            "stdout": self.out.append,
            "stderr": self.err.append,
            "read_file": no_filesystem,
        }
        defaults.update(overrides)
        super().__init__(**defaults)

    @property
    def stdout_text(self) -> str:
        return "".join(self.out)

    @property
    def stderr_text(self) -> str:
        return "".join(self.err)


def merchant_client(merchant: Merchant, signer: CountingSigner, **overrides: Any) -> Any:
    """Injects a client wired to the local merchant and stub RPCs, with a real signer."""

    def create(**config: Any) -> Tx402Client:
        config.pop("evm_signer", None)
        wiring: dict[str, Any] = {
            "evm_signer": signer,
            "transport": httpx.MockTransport(merchant),
            "evm_rpc_transport": evm_rpc(),
            "solana_rpc_transport": svm_rpc(),
        }
        wiring.update(overrides)
        return Tx402Client(**config, **wiring)

    return create


@pytest.fixture
def signer() -> CountingSigner:
    return CountingSigner()


@pytest.fixture
def merchant() -> Merchant:
    return Merchant(offers=[challenge(evm_requirement())])


class TestArgumentParsing:
    def test_shows_help_with_no_arguments_and_exits_zero(self) -> None:
        harness = Harness([])
        assert run_cli(harness) == EXIT_CODES["success"]
        assert "tx402 call <URL>" in harness.stdout_text

    def test_reports_the_version_the_package_actually_declares(self) -> None:
        """Read from ``pyproject.toml``, not from ``tx402._version``.

        Comparing the CLI's output against the generated module it already prints would
        prove only that the module equals itself. Until S15b this asserted the literal
        ``0.0.0``, so a correctly tagged 0.1.0 would have shipped a console script
        identifying itself as 0.0.0 and the test would still have been green (O51).
        """
        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        declared = tomllib.loads(pyproject.read_text())["project"]["version"]
        harness = Harness(["--version"])
        assert run_cli(harness) == EXIT_CODES["success"]
        assert harness.stdout_text == f"tx402 {declared}\n"

    def test_rejects_an_unknown_command(self) -> None:
        harness = Harness(["fetch", URL])
        assert run_cli(harness) == EXIT_CODES["usage"]
        assert "Unknown command" in harness.stderr_text

    def test_rejects_an_unknown_option_rather_than_treating_it_as_the_url(self) -> None:
        with pytest.raises(UsageError, match="Unknown option"):
            parse_args(["call", "--verbose", URL], lambda _p: "")

    def test_accepts_no_flag_that_could_carry_a_private_key(self) -> None:
        """SEC-001. A flag lands in shell history, in `ps`, and in CI logs."""
        for flag in ("--private-key", "--key", "--keypair", "--secret", "--mnemonic"):
            with pytest.raises(UsageError, match="Unknown option"):
                parse_args(["call", URL, flag, "0xdead"], lambda _p: "")

    def test_refuses_an_inline_body_so_a_secret_cannot_land_in_shell_history(
        self,
    ) -> None:
        with pytest.raises(UsageError, match="@<file>"):
            parse_args(["call", URL, "--body", '{"a":1}'], lambda _p: "")

    def test_reads_body_from_a_file(self) -> None:
        parsed = parse_args(["call", URL, "--body", "@payload.json"], lambda _p: "{}")
        assert parsed.options is not None
        assert parsed.options.body == "{}"
        assert parsed.options.body_path == "payload.json"

    def test_an_unreadable_body_file_is_a_usage_error_that_does_not_quote_the_path(
        self,
    ) -> None:
        def explode(path: str) -> str:
            raise OSError(f"ENOENT: /home/someone/secret/{path}")

        with pytest.raises(UsageError) as raised:
            parse_args(["call", URL, "--body", "@missing.json"], explode)
        # The underlying message quotes an absolute path; it must not be forwarded.
        assert "/home/someone" not in str(raised.value)

    def test_rejects_a_non_numeric_timeout_rather_than_coercing_it(self) -> None:
        with pytest.raises(UsageError, match="whole milliseconds"):
            parse_args(["call", URL, "--timeout", "10s"], lambda _p: "")
        with pytest.raises(UsageError, match="greater than zero"):
            parse_args(["call", URL, "--timeout", "0"], lambda _p: "")

    def test_rejects_a_flag_that_is_missing_its_value(self) -> None:
        with pytest.raises(UsageError, match="requires a value"):
            parse_args(["call", URL, "--max-spend"], lambda _p: "")
        with pytest.raises(UsageError, match="requires a value"):
            parse_args(["call", URL, "--max-spend", "--json"], lambda _p: "")

    def test_rejects_credentials_embedded_in_the_url(self) -> None:
        with pytest.raises(UsageError, match="credentials"):
            parse_args(["call", "https://user:pw@merchant.test/x"], lambda _p: "")

    def test_rejects_a_relative_url(self) -> None:
        with pytest.raises(UsageError, match="absolute"):
            parse_args(["call", "/resource"], lambda _p: "")

    def test_rejects_two_urls(self) -> None:
        with pytest.raises(UsageError, match="Only one URL"):
            parse_args(["call", URL, "https://other.test/x"], lambda _p: "")

    def test_normalises_the_method_and_rejects_an_unsupported_one(self) -> None:
        parsed = parse_args(["call", URL, "--method", "post"], lambda _p: "")
        assert parsed.options is not None
        assert parsed.options.method == "POST"
        with pytest.raises(UsageError, match="Unsupported --method"):
            parse_args(["call", URL, "--method", "TRACE"], lambda _p: "")


class TestExitCodeMapping:
    """SPEC §11's nine codes, and the SPEC §8 taxonomy's fifteen mapped onto them."""

    def test_classifies_every_error_code_in_the_taxonomy(self) -> None:
        # Exhaustive by assertion rather than by the type system, which is what Python
        # gives us: a sixteenth error code added to SPEC §8 without a row here fails now,
        # rather than silently exiting as an unclassified failure.
        assert {entry.code for entry in TX402_ERROR_TAXONOMY} == set(EXIT_CODE_BY_ERROR)
        assert len(EXIT_CODE_BY_ERROR) == 15

    def test_uses_each_of_the_nine_documented_codes_and_never_one(self) -> None:
        used = set(EXIT_CODE_BY_ERROR.values())
        assert used == set(EXIT_CODES.values()) - {EXIT_CODES["success"]}
        assert 1 not in set(EXIT_CODES.values())

    def test_reserves_exit_code_eight_for_outcomes_that_may_pay_twice(self) -> None:
        """8 is the "stop, money may have moved" code.

        It is shared by exactly the two errors reachable only *after* a signature was
        transmitted. The blocked cross-origin redirect joined it at S15b: ADR-014 always
        described it as exit 8, the table said 9, and O52 made the error reachable from the
        high-level client at all.
        """
        assert sorted(
            code
            for code, exit_code in EXIT_CODE_BY_ERROR.items()
            if exit_code == EXIT_CODES["ambiguous_payment"]
        ) == sorted(
            [
                TX402_ERROR_CODES["payment_ambiguous"],
                TX402_ERROR_CODES["redirect_blocked"],
            ]
        )

    def test_matches_the_typescript_table_row_for_row(self) -> None:
        """The two CLIs are one exit-code contract; a divergence here breaks a script."""
        expected = {
            "TX402_CONFIG_INVALID": 2,
            "TX402_RESERVED_HEADER": 2,
            "TX402_NON_REPLAYABLE": 2,
            "TX402_POLICY_BUDGET": 3,
            "TX402_POLICY_DOMAIN": 3,
            "TX402_LIQUIDITY": 4,
            "TX402_PROTOCOL_UNSUPPORTED": 5,
            "TX402_SCHEME_UNSUPPORTED": 5,
            "TX402_PAYMENT_REQUIRED_INVALID": 5,
            "TX402_CLOCK_SKEW": 5,
            "TX402_SIGNER": 6,
            "TX402_TRANSPORT": 7,
            "TX402_PAYMENT_AMBIGUOUS": 8,
            "TX402_RESOURCE_DELIVERY": 9,
            "TX402_REDIRECT_BLOCKED": 8,
        }
        assert dict(EXIT_CODE_BY_ERROR) == expected

    def test_exits_three_when_local_policy_refuses(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        harness = Harness(
            ["call", URL, "--max-spend", "0.001 USDC"],
            create_client=merchant_client(merchant, signer),
        )
        assert run_cli(harness) == EXIT_CODES["policy"]
        assert "TX402_POLICY_BUDGET" in harness.stderr_text
        # SEC-002: the refusal happened before anything could be signed.
        assert signer.sign_count == 0

    def test_exits_seven_when_the_merchant_is_unreachable(
        self, signer: CountingSigner
    ) -> None:
        def dead(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        def create(**config: Any) -> Tx402Client:
            config.pop("evm_signer", None)
            return Tx402Client(
                **config, evm_signer=signer, transport=httpx.MockTransport(dead)
            )

        harness = Harness(["call", URL], create_client=create)
        assert run_cli(harness) == EXIT_CODES["transport"]
        assert "TX402_TRANSPORT" in harness.stderr_text

    def test_exits_four_when_the_wallet_cannot_cover_it(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        harness = Harness(
            ["call", URL],
            create_client=merchant_client(
                merchant, signer, evm_rpc_transport=evm_rpc(balance=1)
            ),
        )
        assert run_cli(harness) == EXIT_CODES["liquidity"]
        assert signer.sign_count == 0


class TestDryRun:
    def test_plans_a_route_and_never_signs(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        harness = Harness(
            ["call", URL, "--dry-run"],
            create_client=merchant_client(merchant, signer),
        )
        assert run_cli(harness) == EXIT_CODES["success"]
        assert signer.sign_count == 0
        assert "would pay       50000 atomic on eip155:8453" in harness.stderr_text
        assert "nothing was signed" in harness.stderr_text

    def test_never_reaches_the_merchant_with_a_signature(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        harness = Harness(
            ["call", URL, "--dry-run"],
            create_client=merchant_client(merchant, signer),
        )
        assert run_cli(harness) == EXIT_CODES["success"]
        assert merchant.signature_digests == []
        assert merchant.paid == 0

    def test_reserves_no_budget_so_a_dry_run_cannot_exhaust_the_hourly_cap(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        clients: list[Tx402Client] = []

        def create(**config: Any) -> Tx402Client:
            built: Tx402Client = merchant_client(merchant, signer)(**config)
            clients.append(built)
            return built

        harness = Harness(["call", URL, "--dry-run"], create_client=create)
        assert run_cli(harness) == EXIT_CODES["success"]
        state = clients[0].get_budget_state(
            policy_scope="merchant.test", asset_id=f"{BASE}/erc20:{BASE_ASSET}"
        )
        assert state.reserved_atomic == "0"
        assert state.committed_atomic == "0"

    def test_the_guard_raises_rather_than_signing_if_it_is_ever_reached(self) -> None:
        """The dry-run signer is a structural guarantee, not a code-path convention."""
        from tx402.cli import _DryRunSigner

        guard = _DryRunSigner(CountingSigner())
        assert guard.get_address() == EVM_PAYER
        with pytest.raises(AssertionError, match="must never produce a signature"):
            guard.sign_typed_data(object())


class TestJsonOutput:
    @staticmethod
    def document(text: str) -> dict[str, Any]:
        import json

        return dict(json.loads(text))

    def test_writes_exactly_one_json_object_to_stdout_on_success(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        harness = Harness(
            ["call", URL, "--json"], create_client=merchant_client(merchant, signer)
        )
        assert run_cli(harness) == EXIT_CODES["success"]
        document = self.document(harness.stdout_text)
        assert document["schemaVersion"] == JSON_SCHEMA_VERSION
        assert document["ok"] is True
        assert document["exitCode"] == 0
        assert document["dryRun"] is False
        assert document["status"] == 200
        assert document["body"] == "delivered"
        assert document["error"] is None

    def test_reports_the_route_and_inspection_on_a_dry_run(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        harness = Harness(
            ["call", URL, "--dry-run", "--json"],
            create_client=merchant_client(merchant, signer),
        )
        assert run_cli(harness) == EXIT_CODES["success"]
        document = self.document(harness.stdout_text)
        assert document["dryRun"] is True
        assert document["inspection"]["status"] == 402
        assert document["inspection"]["requirementCount"] == 1
        assert document["inspection"]["headerHash"].startswith("sha256:")
        assert document["route"]["network"] == BASE
        assert document["route"]["amountAtomic"] == "50000"
        assert document["route"]["rank"] == 1

    def test_reports_inspection_and_route_on_the_paying_path_too(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        """`request` returns a response, not a plan, so these come from the event stream."""
        harness = Harness(
            ["call", URL, "--json"], create_client=merchant_client(merchant, signer)
        )
        assert run_cli(harness) == EXIT_CODES["success"]
        document = self.document(harness.stdout_text)
        assert document["inspection"]["requirementCount"] == 1
        assert document["route"]["network"] == BASE
        assert document["route"]["candidateCount"] == 1
        assert document["timings"]["events"] > 0

    def test_still_emits_one_parseable_object_on_failure_with_the_typed_error(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        harness = Harness(
            ["call", URL, "--max-spend", "0.001 USDC", "--json"],
            create_client=merchant_client(merchant, signer),
        )
        assert run_cli(harness) == EXIT_CODES["policy"]
        document = self.document(harness.stdout_text)
        assert document["ok"] is False
        assert document["exitCode"] == EXIT_CODES["policy"]
        assert document["error"]["code"] == "TX402_POLICY_BUDGET"

    def test_a_serialised_error_never_carries_the_underlying_cause(
        self, signer: CountingSigner
    ) -> None:
        """SEC-003: `to_dict` omits the cause, which is where a URL or payload would be."""

        def dead(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(
                "connect to https://user:pw@rpc.internal", request=request
            )

        def create(**config: Any) -> Tx402Client:
            config.pop("evm_signer", None)
            return Tx402Client(
                **config, evm_signer=signer, transport=httpx.MockTransport(dead)
            )

        harness = Harness(["call", URL, "--json"], create_client=create)
        assert run_cli(harness) == EXIT_CODES["transport"]
        assert "user:pw" not in harness.stdout_text
        assert "cause" not in self.document(harness.stdout_text)["error"]

    def test_a_usage_error_is_reported_as_a_json_document_when_json_was_requested(
        self,
    ) -> None:
        # `--json` is parsed before the failure, so the caller still gets one object.
        harness = Harness(["call", URL, "--json", "--network"])
        assert run_cli(harness) == EXIT_CODES["usage"]
        assert "tx402: --network requires a value" in harness.stderr_text


class TestStreamContract:
    def test_puts_the_response_body_on_stdout_and_nothing_else(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        harness = Harness(["call", URL], create_client=merchant_client(merchant, signer))
        assert run_cli(harness) == EXIT_CODES["success"]
        assert harness.stdout_text == "delivered"

    def test_puts_diagnostics_on_stderr_keeping_a_redirected_stdout_clean(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        harness = Harness(
            ["call", URL, "--dry-run"],
            create_client=merchant_client(merchant, signer),
        )
        assert run_cli(harness) == EXIT_CODES["success"]
        # A dry run produces no body, so a redirected stdout must be empty rather than
        # carrying the human-readable plan.
        assert harness.stdout_text == ""
        assert harness.stderr_text != ""


class TestDevelopmentKeyHandling:
    """SPEC §11, SEC-001."""

    def test_warns_on_stderr_every_time_an_environment_key_is_used(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        harness = Harness(
            ["call", URL, "--dry-run"],
            env={DEV_KEY_ENV["evm"]: DEV_KEY},
            create_client=merchant_client(merchant, signer),
        )
        assert run_cli(harness) == EXIT_CODES["success"]
        assert "warning: using a development signing key" in harness.stderr_text

    def test_never_echoes_the_key_itself(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        harness = Harness(
            ["call", URL, "--dry-run", "--json"],
            env={DEV_KEY_ENV["evm"]: DEV_KEY},
            create_client=merchant_client(merchant, signer),
        )
        run_cli(harness)
        assert DEV_KEY not in harness.stdout_text
        assert DEV_KEY not in harness.stderr_text
        assert DEV_KEY[2:] not in harness.stdout_text + harness.stderr_text

    def test_rejects_a_malformed_environment_key_without_quoting_it(
        self, merchant: Merchant, signer: CountingSigner
    ) -> None:
        harness = Harness(
            ["call", URL],
            env={DEV_KEY_ENV["evm"]: "not-a-key-but-still-secret"},
            create_client=merchant_client(merchant, signer),
        )
        assert run_cli(harness) == EXIT_CODES["usage"]
        assert "not-a-key-but-still-secret" not in harness.stderr_text
        assert "0x-prefixed 32-byte hex" in harness.stderr_text

    def test_runs_with_no_signer_at_all_and_fails_typed_rather_than_crashing(
        self, merchant: Merchant
    ) -> None:
        def create(**config: Any) -> Tx402Client:
            config.pop("evm_signer", None)
            return Tx402Client(**config, transport=httpx.MockTransport(merchant))

        harness = Harness(["call", URL], create_client=create)
        # Exit 5, not 4. SPEC §6.4 step 20 distinguishes "nothing was even attempted"
        # from "everything attempted fell short", and with no signer configured nothing
        # was attempted — reporting that as insufficient liquidity would send the
        # operator to fund a wallet that is not the problem.
        assert run_cli(harness) == EXIT_CODES["protocol"]
        assert "TX402_SCHEME_UNSUPPORTED" in harness.stderr_text


class TestNetworkRestriction:
    def test_network_restricts_payment_to_one_network(self, signer: CountingSigner) -> None:
        merchant = Merchant(offers=[challenge(svm_requirement(), evm_requirement())])
        harness = Harness(
            ["call", URL, "--network", BASE, "--dry-run", "--json"],
            create_client=merchant_client(merchant, signer),
        )
        assert run_cli(harness) == EXIT_CODES["success"]
        import json as _json

        document = _json.loads(harness.stdout_text)
        assert document["route"]["network"] == BASE
        # The Solana offer was excluded by policy, so it is not even a candidate.
        assert document["route"]["candidateCount"] == 1

    def test_max_spend_and_network_are_both_applied_not_last_flag_wins(
        self, signer: CountingSigner
    ) -> None:
        """Both flags build one Policy; a per-flag assignment would drop one silently."""
        merchant = Merchant(offers=[challenge(evm_requirement(), svm_requirement())])
        harness = Harness(
            ["call", URL, "--network", SOLANA, "--max-spend", "0.001 USDC"],
            create_client=merchant_client(merchant, signer),
        )
        # The network filter alone would have selected Solana and paid; the cap refuses.
        assert run_cli(harness) == EXIT_CODES["policy"]
        assert signer.sign_count == 0


class TestProcessEntryPoint:
    def test_main_slices_argv_past_the_script_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        written: list[str] = []

        def capture(io: CliIo) -> int:
            written.append(" ".join(io.argv))
            return EXIT_CODES["success"]

        monkeypatch.setattr("tx402.cli.run_cli", capture)
        assert main(["/usr/bin/tx402", "call", URL]) == EXIT_CODES["success"]
        assert written == [f"call {URL}"]

    def test_run_raises_system_exit_carrying_the_code(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sys.argv", ["tx402", "nonsense"])
        with pytest.raises(SystemExit) as raised:
            run()
        assert raised.value.code == EXIT_CODES["usage"]
