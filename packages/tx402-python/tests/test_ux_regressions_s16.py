"""Regressions for the S16 fresh-eyes UX pass (§11.3), open items O64, O68, O71.

The twin of ``packages/tx402/test/ux-regressions-s16.test.ts``. Both were run against
``00c1685`` first to confirm they failed there; a regression that passes before the fix is
not evidence.

Only the findings with a Python side appear here. O64's requirement fixture is shared —
``tools/test-merchant`` is a Node process that Python spawns — so this file asserts the
published requirement sets are payable *as data*, which is the half Python can see without
re-implementing the chain planners. O71(a) is a genuine parity item: ``emit`` uses
``getattr(logger, level)`` under ``suppress(Exception)``, so a callable passed where SPEC
§10 requires an object produced zero events and no error, exactly as TypeScript did.
"""

from __future__ import annotations

import json
import subprocess
from functools import lru_cache
from pathlib import Path

import pytest

from tx402 import Tx402Client
from tx402.errors import ConfigurationError

REPO = Path(__file__).resolve().parents[3]
EXAMPLES = REPO / "examples"
REQUIREMENTS = REPO / "tools" / "test-merchant" / "scenarios.js"


@lru_cache(maxsize=1)
def _default_requirements() -> str:
    """Ask Node for ``DEFAULT_REQUIREMENTS``, as JSON.

    Evaluated rather than parsed. The fixture is JavaScript, and a regex that turns it into
    JSON is a second implementation of a parser — the exact "plausible transcription"
    problem ``tools/docs-gen`` exists to avoid. Node already runs in this suite to host the
    test merchant, so asking the module for its own value costs nothing and cannot drift.

    Returns the raw JSON text; callers parse it, so the cache holds an immutable value.
    """
    result = subprocess.run(
        [
            "node",
            "--input-type=module",
            "-e",
            f"const m = await import({json.dumps(REQUIREMENTS.as_uri())});"
            "process.stdout.write(JSON.stringify(m.DEFAULT_REQUIREMENTS));",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if (
        result.returncode != 0
    ):  # pragma: no cover - a broken fixture fails the Node suite too
        pytest.fail(f"could not read DEFAULT_REQUIREMENTS: {result.stderr.strip()}")
    return result.stdout


def _requirements() -> dict[str, dict[str, object]]:
    parsed: dict[str, dict[str, object]] = json.loads(_default_requirements())
    return parsed


EVM_SETS = ("base", "baseSepolia")
SVM_SETS = ("solana", "solanaDevnet")


class TestO64DocumentedRequirementsArePayable:
    """The merchant the quickstart tells a reader to start must emit a payable challenge."""

    @pytest.mark.parametrize("key", EVM_SETS)
    def test_evm_sets_carry_an_eip712_domain(self, key: str) -> None:
        extra = _requirements()[key]["extra"]
        assert isinstance(extra, dict)
        # Upstream's EIP-3009 flow refuses to sign without both, and tx402 declines rather
        # than burning a nonce on a signature the token would reject.
        name = extra.get("name")
        assert isinstance(name, str)
        assert name
        assert extra.get("version") == "2"

    @pytest.mark.parametrize("key", SVM_SETS)
    def test_svm_sets_name_a_fee_payer(self, key: str) -> None:
        extra = _requirements()[key]["extra"]
        assert isinstance(extra, dict)
        fee_payer = extra.get("feePayer")
        # An SPL transfer needs a fee payer; without one the buyer sees the opaque
        # "Solana requirement is missing an address" that S16 spent time diagnosing.
        assert isinstance(fee_payer, str)
        assert fee_payer


class TestO68ExamplesAcceptTheDocumentedMerchant:
    """The docs' inline snippet opts into localhost; the runnable files did not."""

    @pytest.mark.parametrize("name", ["quickstart.py", "dry_run.py"])
    def test_python_examples_opt_into_localhost(self, name: str) -> None:
        source = (EXAMPLES / "python" / name).read_text(encoding="utf-8")
        assert "allow_insecure_localhost" in source


class TestO71ExamplesAreDocumented:
    """``TX402_MERCHANT_URL`` appeared only in the error you get for not setting it."""

    def test_examples_readme_exists_and_names_the_variable(self) -> None:
        readme = EXAMPLES / "README.md"
        assert readme.is_file()
        assert "TX402_MERCHANT_URL" in readme.read_text(encoding="utf-8")


class TestO71aLoggerIsValidated:
    """SPEC §10 specifies an object with debug/info/warn/error, not a callable.

    ``emit`` suppresses logger failures on purpose — a logger fault must never fail a
    payment that already settled — and that is what turned a misconfigured hook into
    silence. The suppression stays; the construction-time check is what was missing.
    """

    @pytest.mark.parametrize(
        "logger",
        [
            pytest.param(lambda event: None, id="callable"),
            pytest.param(object(), id="bare-object"),
            pytest.param(
                type("Partial", (), {"info": lambda self, event: None})(), id="partial"
            ),
        ],
    )
    def test_rejects_a_logger_that_is_not_the_contract(self, logger: object) -> None:
        with pytest.raises(ConfigurationError, match="logger"):
            Tx402Client(logger=logger)  # type: ignore[arg-type]

    def test_still_accepts_a_complete_logger(self) -> None:
        class Complete:
            def debug(self, event: object) -> None: ...
            def info(self, event: object) -> None: ...
            def warn(self, event: object) -> None: ...
            def error(self, event: object) -> None: ...

        # No `type: ignore` here, deliberately: a complete logger must satisfy the
        # Tx402Logger protocol structurally, so this line type-checking is part of
        # the claim.
        with Tx402Client(logger=Complete()):
            pass
