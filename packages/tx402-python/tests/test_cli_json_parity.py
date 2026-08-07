"""Cross-language CLI ``--json`` parity (PLAN.md open item **O107**).

``docs/src/content/docs/guides/cli.mdx`` opens by promising both packages emit "the same
``--json`` document". S34 drove both CLIs across all 17 test-merchant scenarios and found
the Python CLI dropped the route fields — ``network``, ``scheme``, ``amountAtomic``,
``assetId`` — from ``error.context`` on every post-routing failure, and diverged again on
``rechallenge-malformed``'s ``details`` and ``message``. Nothing in the gate set diffed the
two documents, so it shipped.

The canonical document is ``core-spec/cli-json/expected.json``, generated from the
TypeScript CLI by ``tools/cli-parity`` and re-derived live by its TypeScript twin
(``packages/tx402/test/cli-json-parity.test.ts``). This module pins the **Python** CLI to
the same golden: it runs the real Python CLI in process against the real deterministic Node
test merchant, normalizes exactly as the tool does, and asserts equality scenario by
scenario. A change in either language now fails a test.

**Coverage note (not a silent cap).** The merchant is the Node ``tools/test-merchant``
process, which needs the TypeScript workspace's ``node_modules``. Where those are absent —
the Linux ``python`` CI matrix runs no ``pnpm install`` — the whole module skips with the
reason below, and the parity is instead exercised on every push by the ``cross-platform``
job (macOS and Windows, which build the workspace) plus the TypeScript ``check`` gate. It
always runs locally and in any job that has installed the workspace.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from tx402 import cli as cli_module
from tx402.client import Tx402Client

REPO = Path(__file__).resolve().parents[3]
GOLDEN = REPO / "core-spec" / "cli-json" / "expected.json"
MERCHANT = REPO / "tools" / "test-merchant" / "cli.js"
DEV_KEY = "0xa11ce00000000000000000000000000000000000000000000000000000000001"

#: Erased before comparison — the same set ``tools/cli-parity/index.js`` uses. The two lists
#: must not drift; each is a field the SDK does not promise to reproduce byte for byte.
VOLATILE_KEYS = {
    "requestId",
    "reservationId",
    "elapsedMs",
    "headerHash",
    "healthScore",
    "body",
    "fromOrigin",
    "toOrigin",
}


def _normalize(value: Any) -> Any:
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {
            key: "<normalized>"
            if key in VOLATILE_KEYS or re.search(r"EpochMs$", key)
            else _normalize(inner)
            for key, inner in value.items()
        }
    return value


def _merchant_available() -> bool:
    """True when the Node test merchant can actually start (its deps are installed)."""
    if not MERCHANT.is_file():
        return False
    try:
        proc = subprocess.Popen(
            [
                "node",
                str(MERCHANT),
                "--scenario",
                "pay-once",
                "--requirements",
                "base",
                "--port",
                "0",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            cwd=str(REPO),
        )
    except FileNotFoundError:
        return False
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline()
        json.loads(line)
        return True
    except (ValueError, AssertionError):
        return False
    finally:
        proc.terminate()
        proc.wait()


pytestmark = pytest.mark.skipif(
    not _merchant_available(),
    reason="Node test-merchant is unavailable (workspace node_modules absent); CLI --json "
    "parity is covered by the cross-platform CI job and the TypeScript check gate.",
)


def _evm_rpc(balance: int = 5_000_000, chain_id: int = 8453) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        document = json.loads(request.read())
        result = hex(chain_id) if document["method"] == "eth_chainId" else hex(balance)
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": document["id"], "result": result}
        )

    return httpx.MockTransport(handle)


def _run_python_cli(url: str) -> dict[str, Any]:
    out: list[str] = []

    def create_client(**kwargs: Any) -> Tx402Client:
        kwargs["evm_rpc_transport"] = _evm_rpc()
        return Tx402Client(**kwargs)

    io = cli_module.CliIo(
        argv=[
            "call",
            f"{url}/resource",
            "--max-spend",
            "0.10 USDC",
            "--timeout",
            "1500",
            "--json",
        ],
        env={"TX402_DEV_PRIVATE_KEY": DEV_KEY},
        stdout=out.append,
        stderr=lambda _text: None,
        create_client=create_client,
    )
    exit_code = cli_module.run_cli(io)
    return {"exitCode": exit_code, "json": _normalize(json.loads("".join(out)))}


def _golden() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(GOLDEN.read_text(encoding="utf-8"))
    return data


@pytest.mark.parametrize("scenario", sorted(_golden().keys()))
def test_python_cli_json_matches_the_cross_language_golden(scenario: str) -> None:
    proc = subprocess.Popen(
        [
            "node",
            str(MERCHANT),
            "--scenario",
            scenario,
            "--requirements",
            "base",
            "--port",
            "0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        cwd=str(REPO),
    )
    try:
        assert proc.stdout is not None
        info = json.loads(proc.stdout.readline())
        actual = _run_python_cli(info["url"])
    finally:
        proc.terminate()
        proc.wait()

    expected = _golden()[scenario]
    assert actual["exitCode"] == expected["exitCode"], scenario
    assert actual["json"] == expected["json"], scenario
