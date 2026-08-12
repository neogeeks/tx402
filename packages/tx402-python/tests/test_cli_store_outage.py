"""O53 (S14g) / U12 (S14h): an operator verb against an unreachable raw-Redis store must
exit 7 (TX402_TRANSPORT, retryable), NOT 2 (TX402_CLI_USAGE) -- the exit-code contract in
``cli.mdx`` (a verb whose store is unreachable raises a TransportError, exactly as a reserve
against that store would).

Mirrors ``packages/tx402/test/cli-store-outage.test.ts``. ``budget`` was covered by U9; S14i
extends this to ``pins`` (json AND non-json), which the S14f fix left exiting 2 because its
recipient-pin read methods were left unwrapped. Drives the real CLI in process against a
dead port (no live Redis needed), and asserts the raw redis-py internals -- which embed the
store ``host:port`` -- do not leak (SEC-003; ADR-023 -- a test that RUNS it).
"""

from __future__ import annotations

import json
from typing import Any

from tx402 import cli as cli_module

_DEAD_STORE = "redis://127.0.0.1:6399"  # nothing listens here
_EXIT_TRANSPORT = 7
_EXIT_USAGE = 2


def _run(argv: list[str], env: dict[str, str]) -> dict[str, Any]:
    out: list[str] = []
    err: list[str] = []
    io = cli_module.CliIo(argv=argv, env=env, stdout=out.append, stderr=err.append)
    code = cli_module.run_cli(io)
    return {"code": code, "out": "".join(out), "err": "".join(err)}


def _assert_no_raw_leak(*streams: str) -> None:
    for stream in streams:
        assert "6399" not in stream
        assert "Connection refused" not in stream
        assert "ConnectionError" not in stream
        assert "Connection is closed" not in stream


def test_pins_json_exits_7_typed_transport_not_usage() -> None:
    result = _run(
        ["pins", "api.merchant.example", "--network", "eip155:8453", "--json"],
        {"TX402_SPEND_STORE": _DEAD_STORE},
    )
    assert result["code"] == _EXIT_TRANSPORT  # 7, not 2 — the O53 regression
    document = json.loads(result["out"])
    assert document["exitCode"] == _EXIT_TRANSPORT
    assert document["error"]["code"] == "TX402_TRANSPORT"
    assert document["error"]["details"]["causeCategory"] == "spend-store-unavailable"
    _assert_no_raw_leak(result["out"], result["err"])


def test_pins_non_json_exits_7_no_raw_leak() -> None:
    result = _run(
        ["pins", "api.merchant.example", "--network", "eip155:8453"],
        {"TX402_SPEND_STORE": _DEAD_STORE},
    )
    assert result["code"] == _EXIT_TRANSPORT
    assert "TX402_TRANSPORT" in result["err"]
    _assert_no_raw_leak(result["out"], result["err"])


def test_budget_json_exits_7_typed_transport() -> None:
    # The U9 case, re-asserted from Python so both CLIs share one exit-code contract.
    result = _run(
        ["budget", "api.merchant.example", "--network", "eip155:8453", "--json"],
        {"TX402_SPEND_STORE": _DEAD_STORE},
    )
    assert result["code"] == _EXIT_TRANSPORT
    document = json.loads(result["out"])
    assert document["error"]["code"] == "TX402_TRANSPORT"
    _assert_no_raw_leak(result["out"], result["err"])
