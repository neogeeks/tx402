"""Regressions for the fourth fresh-eyes UX pass (§11.3), open item O91.

Run against ``75c1c98`` first and observed to fail there.

O91 was introduced by the previous remediation session, and by a *decision* recorded in an
ADR rather than by an oversight — which makes it the more interesting failure of the two
kinds. ADR-021 chose to report ``configPath: "timeouts.initialRequestMs"`` from Python so
that the same mistake would read identically in both languages (ADR-005 cross-language
consistency). That reasoning collides with intra-language consistency, which is stronger
here: every other Python ``configPath`` uses the Python spelling — including this
field's own sibling ``payment_retry_timeout_ms``, which the same change left untouched.

And it pointed a Python reader at a path that the configuration page, written in that same
commit, says does not exist in Python: "Python takes them as flat keyword arguments and
exports no Timeouts type … a Python reader who follows only the TypeScript spelling
constructs something that does not exist." A diagnostic that names a nonexistent path is
worse than one that differs across languages. See the ADR-021 amendment.
"""

from __future__ import annotations

import pytest

from tx402 import Policy, RoutingPolicy, Tx402Client
from tx402.errors import ConfigurationError


def _config_path(**kwargs: object) -> str:
    with pytest.raises(ConfigurationError) as caught:
        Tx402Client(**kwargs)  # type: ignore[arg-type]
    return str(caught.value.details["configPath"])


def test_initial_request_timeout_reports_the_python_spelling() -> None:
    """The finding itself. The keyword the caller typed is the one they are told about."""
    assert _config_path(initial_request_timeout_ms=0) == "initial_request_timeout_ms"
    assert _config_path(initial_request_timeout_ms=1500.5) == "initial_request_timeout_ms"


def test_it_never_names_a_path_python_does_not_accept() -> None:
    """``timeouts`` is not a Python keyword argument, so no Python error may name one.

    Asserted against the constructor rather than against a string, so it stays true if the
    spelling changes again.
    """
    for bad in (0, -1, 1.5, "1000"):
        path = _config_path(initial_request_timeout_ms=bad)
        assert "timeouts." not in path, path
        assert path.islower() or "_" in path, path

    with pytest.raises(TypeError, match="timeouts"):
        Tx402Client(timeouts={"initialRequestMs": 5000})  # type: ignore[call-arg]


def test_every_python_config_path_uses_python_spelling() -> None:
    """The general rule the finding was one violation of.

    A camelCase segment in a Python ``configPath`` is the signature of a path copied across
    from the TypeScript surface, which is how this one arrived.
    """
    paths = [
        _config_path(initial_request_timeout_ms=0),
        _config_path(payment_retry_timeout_ms=500),
        _config_path(policy=Policy(max_paid_attempts=9)),
        _config_path(policy=Policy(allowed_networks=["not-a-caip2"])),
        _config_path(routing=RoutingPolicy(rpc_overrides={"solana:devnet": []})),
        _config_path(logger=lambda event: None),
    ]
    for path in paths:
        for segment in path.replace("[", ".").replace("]", "").split("."):
            assert segment == segment.lower(), f"{path} has a camelCase segment: {segment}"


def test_the_sibling_field_still_reports_its_own_name() -> None:
    """The do-not-regress half: fixing one spelling must not disturb the other."""
    assert _config_path(payment_retry_timeout_ms=500) == "payment_retry_timeout_ms"
