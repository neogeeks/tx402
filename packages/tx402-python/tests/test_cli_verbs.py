"""The operator verbs (SPEC §10): ``freeze``, ``unfreeze``, ``budget``, ``pins``,
``rotate-recipient``.

Mirrors ``packages/tx402/test/cli-verbs.test.ts`` assertion for assertion — the two CLIs are
one command surface with one exit-code contract, and it stays true only if both suites ask
the same questions (ADR-023: tests run the behaviour). The verb-logic tests inject
a real ``MemorySpendStore`` in place of the resolved store, so every assertion is about the
actual store effect; the store-config tests drive the real resolver through the environment.
The cross-language ``--json`` shapes are pinned separately by the CLI-json golden (ADR-024).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import pytest

from tx402 import cli as cli_module
from tx402.ledger import BudgetLimits, MemorySpendStore, ReservationRef

SCOPE = "api.merchant.example"
NETWORK = "eip155:8453"
ASSET_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
ASSET_ID = f"{NETWORK}/erc20:{ASSET_ADDRESS}"
PIN_A = "0x1111111111111111111111111111111111111111"
PIN_B = "0x2222222222222222222222222222222222222222"


def _run(argv: list[str], env: dict[str, str] | None = None) -> dict[str, Any]:
    out: list[str] = []
    err: list[str] = []
    io = cli_module.CliIo(argv=argv, env=env or {}, stdout=out.append, stderr=err.append)
    code = cli_module.run_cli(io)
    return {"code": code, "out": "".join(out), "err": "".join(err)}


def _use_store(
    monkeypatch: pytest.MonkeyPatch, store: MemorySpendStore, kind: str = "gateway"
) -> None:
    """Injects ``store`` as the resolved store, so a verb runs against a real store."""
    monkeypatch.setattr(
        cli_module, "_resolve_store", lambda env, plane: (store, kind, lambda: None)
    )


def _seed_committed(store: MemorySpendStore, amount: str) -> None:
    # The query uses the wall clock; seed with the same clock so the committed spend stays
    # fresh (inside the rolling window), like the TypeScript twin seeds with Date.now().
    now = int(time.time() * 1000)
    result = store.reserve(
        reservation_id=f"t-{amount}",
        request_id=f"req-{amount}",
        policy_scope=SCOPE,
        request_fingerprint=f"fp-{amount}",
        asset_id=ASSET_ID,
        amount_atomic=amount,
        max_per_hour_atomic="1000000000",
        now_epoch_ms=now,
    )
    reservation = result.reservation
    store.commit(
        ref=ReservationRef(
            reservation_id=reservation.reservation_id,
            policy_scope=reservation.policy_scope,
            asset_id=reservation.asset_id,
        ),
        committed_at_epoch_ms=now,
    )


# --- argument parsing -------------------------------------------------------------------


def test_verb_parsing() -> None:
    freeze = cli_module.parse_args(["freeze", SCOPE], lambda _p: "")
    assert freeze.kind == "freeze"
    assert isinstance(freeze.options, cli_module.FreezeOptions)
    budget = cli_module.parse_args(
        ["budget", SCOPE, "--network", NETWORK, "--max-per-hour", "5"], lambda _p: ""
    )
    assert budget.kind == "budget"
    assert isinstance(budget.options, cli_module.BudgetOptions)
    assert budget.options.max_per_hour == "5"
    rotate = cli_module.parse_args(
        ["rotate-recipient", SCOPE, "--network", NETWORK, "--to", PIN_A, PIN_B],
        lambda _p: "",
    )
    assert rotate.kind == "rotate-recipient"
    assert isinstance(rotate.options, cli_module.RotateRecipientOptions)
    assert rotate.options.to == (PIN_A, PIN_B)


def test_verb_parsing_rejects_malformed() -> None:
    for argv, pattern in [
        (["freeze"], "requires a target"),
        (["budget", SCOPE], "--network"),
        (["pins", SCOPE], "--network"),
        (["rotate-recipient", SCOPE, "--network", NETWORK], "--to"),
        (["rotate-recipient", SCOPE, "--network", NETWORK, "--to"], "--to"),
        (["freeze", SCOPE, "--network", NETWORK], "not valid for freeze"),
        (["budget", SCOPE, "--network", NETWORK, "--max-spend", "1"], "not valid"),
        (["frobnicate"], "Unknown command"),
    ]:
        with pytest.raises(cli_module.UsageError, match=pattern):
            cli_module.parse_args(argv, lambda _p: "")


# --- freeze / unfreeze ------------------------------------------------------------------


def test_freeze_and_unfreeze(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemorySpendStore()
    _use_store(monkeypatch, store)
    assert _run(["freeze", SCOPE])["code"] == 0
    assert store.is_frozen(scope=SCOPE) is True
    assert _run(["unfreeze", SCOPE])["code"] == 0
    assert store.is_frozen(scope=SCOPE) is False


def test_freeze_normalizes_and_passes_star(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemorySpendStore()
    _use_store(monkeypatch, store)
    _run(["freeze", "https://API.Merchant.Example/x"])
    assert store.is_frozen(scope=SCOPE) is True
    _run(["freeze", "*"])
    assert store.is_frozen(scope="*") is True


# --- budget (SPEC §10 P1-8b) ------------------------------------------------------------


def test_budget_administered(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemorySpendStore()
    _seed_committed(store, "300000")
    store.set_budget_limits(
        SCOPE,
        ASSET_ID,
        BudgetLimits(max_per_hour_atomic="1000000", max_total_atomic="5000000"),
        1_700_000_000_000,
    )
    _use_store(monkeypatch, store)
    doc = json.loads(
        _run(["budget", SCOPE, "--network", NETWORK, "--asset", ASSET_ADDRESS, "--json"])[
            "out"
        ]
    )
    assert doc["committedAtomic"] == "300000"
    assert doc["limitSource"] == "administered"
    assert doc["availablePerHourAtomic"] == "700000"
    assert doc["availableCumulativeAtomic"] == "4700000"


def test_budget_value_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemorySpendStore()
    _seed_committed(store, "300000")
    _use_store(monkeypatch, store)
    doc = json.loads(
        _run(
            [
                "budget",
                SCOPE,
                "--network",
                NETWORK,
                "--asset",
                ASSET_ADDRESS,
                "--max-per-hour",
                "2000000",
                "--json",
            ]
        )["out"]
    )
    assert doc["limitSource"] == "value-flags"
    assert doc["availablePerHourAtomic"] == "1700000"
    assert doc["cumulativeLimitAtomic"] is None
    assert doc["availableCumulativeAtomic"] is None


def test_budget_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemorySpendStore()
    _seed_committed(store, "300000")
    _use_store(monkeypatch, store)
    doc = json.loads(
        _run(["budget", SCOPE, "--network", NETWORK, "--asset", ASSET_ADDRESS, "--json"])[
            "out"
        ]
    )
    assert doc["limitSource"] == "unknown"
    assert doc["availablePerHourAtomic"] is None
    assert doc["cumulativeConsumedAtomic"] == "300000"


def test_budget_defaults_the_asset(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemorySpendStore()
    _seed_committed(store, "300000")
    _use_store(monkeypatch, store)
    doc = json.loads(_run(["budget", SCOPE, "--network", NETWORK, "--json"])["out"])
    assert doc["asset"] == ASSET_ID


# --- pins / rotate-recipient (SPEC §6/§10) ----------------------------------------------


def test_pins_reads_recipients(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemorySpendStore()
    store.set_recipient_pins(SCOPE, NETWORK, (PIN_A, PIN_B), 1_700_000_000_000)
    # O21: the verb also reports the recipient-policy state for diagnosing TOFU.
    store.set_tofu_enabled(SCOPE, True, 1_700_000_000_000)
    store.set_recipient_assertion_required(SCOPE, True, 1_700_000_000_000)
    _use_store(monkeypatch, store)
    doc = json.loads(_run(["pins", SCOPE, "--network", NETWORK, "--json"])["out"])
    assert doc["recipients"] == [PIN_A, PIN_B]
    assert doc["tofuEnabled"] is True
    assert doc["recipientAssertionRequired"] is True


def test_pins_reports_policy_state_on_human_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # O41c: the HUMAN table mirrors the --json `tofuEnabled`/`recipientAssertionRequired`
    # fields (only the JSON surface was pinned before), so the two CLIs cannot drift on the
    # human surface — matching the TS `tofu enabled … / assertion required …` table.
    store = MemorySpendStore()
    store.set_recipient_pins(SCOPE, NETWORK, (PIN_A,), 1_700_000_000_000)
    store.set_tofu_enabled(SCOPE, True, 1_700_000_000_000)
    store.set_recipient_assertion_required(SCOPE, True, 1_700_000_000_000)
    _use_store(monkeypatch, store)
    out = _run(["pins", SCOPE, "--network", NETWORK])["out"]
    assert re.search(r"tofu enabled\s+true", out)
    assert re.search(r"assertion required\s+true", out)


def test_o33_python_cli_help_cites_no_internal_document() -> None:
    result = _run(["--help"])
    help_text = result["out"]
    assert "Operator verbs" in help_text
    for citation in ("SPEC §", "ADR-", "SEC-", "PLAN.md", "PRD"):
        assert citation not in help_text, f"help cites {citation!r}"


def test_rotate_canonicalizes(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemorySpendStore()
    _use_store(monkeypatch, store)
    mixed = "0xAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaa"
    doc = json.loads(
        _run(
            [
                "rotate-recipient",
                SCOPE,
                "--network",
                NETWORK,
                "--to",
                mixed,
                PIN_B,
                "--json",
            ]
        )["out"]
    )
    assert store.get_recipient_pins(SCOPE, NETWORK) == (mixed.lower(), PIN_B)
    assert doc["recipients"] == [mixed.lower(), PIN_B]


def test_rotate_freeze_before_rotate_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemorySpendStore()
    _use_store(monkeypatch, store, kind="gateway")
    unfrozen = _run(["rotate-recipient", SCOPE, "--network", NETWORK, "--to", PIN_A])
    assert "not frozen" in unfrozen["err"]
    assert "freeze the scope before rotating" in unfrozen["err"]
    # The reader-facing warning must not cite an internal SPEC section (O33).
    assert "§" not in unfrozen["err"]
    assert "SPEC" not in unfrozen["err"]

    store.freeze(SCOPE, 1_700_000_000_000)
    frozen = _run(["rotate-recipient", SCOPE, "--network", NETWORK, "--to", PIN_B])
    assert frozen["err"] == ""


def test_rotate_no_warning_on_redis_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    # Raw Redis co-locates pins and budgets, so rotation is race-free — no warning.
    store = MemorySpendStore()
    _use_store(monkeypatch, store, kind="redis")
    result = _run(["rotate-recipient", SCOPE, "--network", NETWORK, "--to", PIN_A])
    assert result["err"] == ""


# --- store-config resolution (SPEC §9.1) ------------------------------------------------


def test_admin_verb_data_only_credential_is_refused() -> None:
    result = _run(
        ["freeze", SCOPE, "--json"],
        {"TX402_SPEND_STORE": "https://gateway.example", "TX402_SPEND_STORE_TOKEN": "d"},
    )
    assert result["code"] == 2
    doc = json.loads(result["out"])
    assert doc["error"]["details"]["reason"] == "admin-credential-required"


def test_do_dsn_is_refused() -> None:
    result = _run(
        ["pins", SCOPE, "--network", NETWORK, "--json"],
        {"TX402_SPEND_STORE": "do://SPEND_STORE", "TX402_SPEND_STORE_TOKEN": "d"},
    )
    assert result["code"] == 2
    doc = json.loads(result["out"])
    assert doc["error"]["details"]["reason"] == "durable-object-not-a-cli-dsn"


def test_unset_store_is_refused() -> None:
    result = _run(["pins", SCOPE, "--network", NETWORK, "--json"], {})
    doc = json.loads(result["out"])
    assert doc["error"]["details"]["reason"] == "spend-store-unset"


def test_store_outage_maps_to_exit_7() -> None:
    # An unreachable gateway is a transport outage (exit 7), never a crash.
    result = _run(
        ["pins", SCOPE, "--network", NETWORK],
        {"TX402_SPEND_STORE": "http://127.0.0.1:1", "TX402_SPEND_STORE_TOKEN": "d"},
    )
    assert result["code"] == 7
