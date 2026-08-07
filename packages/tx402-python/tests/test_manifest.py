"""Manifest guarantees the conformance vectors cannot cover.

The vectors check verification *behavior* against shared fixtures. These check facts about
this repository: that the embedded copy still matches the signed source, and that the
bundled manifest carries what SPEC §5.4 requires it to carry.

Mirrors ``packages/tx402/test/manifest.test.ts``.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Final

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tests.conformance.runner import REPO_ROOT
from tx402.bundled_manifest import BUNDLED_MANIFEST
from tx402.canonical_json import canonicalize_json
from tx402.errors import ConfigurationError, Tx402ErrorContext
from tx402.manifest import (
    assert_valid_release_manifest,
    require_network,
    resolve_network,
    verify_release_manifest,
)
from tx402.trusted_keys import MANIFEST_SIGNING_DOMAIN, TRUSTED_MANIFEST_KEYS

SOURCE_MANIFEST_PATH: Final = (
    REPO_ROOT / "core-spec" / "manifests" / "bundled.manifest.json"
)

#: The four networks SPEC §5.4 requires the *bundled* manifest to declare.
REQUIRED_NETWORKS: Final = (
    "eip155:8453",
    "eip155:84532",
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
)

#: A moment inside the bundled manifest's validity window.
#:
#: Pinned rather than "now": these assertions must not start failing on the day the manifest
#: expires. Expiry itself is covered by ``manifest.verify.expired``, and the manifest is
#: re-issued through the runbook, not by a test going red.
NOW: Final = 1788220800000.0  # 2026-09-01T00:00:00Z

#: Construction-time context, as the client constructor would supply it.
CONTEXT: Final = Tx402ErrorContext(request_id="construct", phase="initial")

#: An Ed25519 keypair minted for this test run.
#:
#: The release signing key is deliberately not in the repository, so the *content* rules —
#: empty networks, a malformed network key, a dangling alias — cannot be reached with the
#: real key: verification checks the signature first and a hand-mutated manifest fails there
#: instead. Signing with an ephemeral key and overriding ``trusted_keys`` gets past the
#: signature so the checks behind it are exercised, without any secret being committed.
_TEST_PRIVATE_KEY: Final = Ed25519PrivateKey.generate()
TEST_KEY_ID: Final = "tx402-release-1"
TEST_PUBLIC_KEY: Final = base64.b64encode(
    _TEST_PRIVATE_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
).decode("ascii")


def sign_with_test_key(manifest: dict[str, Any]) -> dict[str, Any]:
    """Sign a manifest with the ephemeral key, exactly as tools/manifest-signer would."""
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    signed = MANIFEST_SIGNING_DOMAIN.encode("ascii") + canonicalize_json(unsigned).encode(
        "ascii"
    )
    return {
        **unsigned,
        "signature": {
            "algorithm": "ed25519",
            "keyId": TEST_KEY_ID,
            "value": base64.b64encode(_TEST_PRIVATE_KEY.sign(signed)).decode("ascii"),
        },
    }


def verify_test_signed(manifest: dict[str, Any], now_epoch_ms: float = NOW) -> Any:
    """Verify against the ephemeral key rather than the shipped one."""
    return verify_release_manifest(
        manifest, now_epoch_ms=now_epoch_ms, trusted_keys={TEST_KEY_ID: TEST_PUBLIC_KEY}
    )


class TestBundledManifest:
    def test_is_byte_identical_to_the_signed_source(self) -> None:
        """ADR-012.

        ``src/tx402/bundled_manifest.py`` is generated. If this fails, either someone
        hand-edited the generated file, or the manifest was re-signed without running
        ``node tools/manifest-signer/index.js embed``.
        """
        source: dict[str, Any] = json.loads(SOURCE_MANIFEST_PATH.read_text())
        assert source == BUNDLED_MANIFEST

    def test_verifies_under_the_compiled_in_trusted_key(self) -> None:
        assert verify_release_manifest(BUNDLED_MANIFEST, now_epoch_ms=NOW).valid

    def test_declares_all_four_required_networks(self) -> None:
        """SPEC §5.4."""
        result = verify_release_manifest(
            BUNDLED_MANIFEST, now_epoch_ms=NOW, required_networks=REQUIRED_NETWORKS
        )
        assert result.valid, result.message

    def test_keys_solana_networks_on_genesis_hashes_not_the_alias(self) -> None:
        """ADR-010 decision 4."""
        network_ids = set(BUNDLED_MANIFEST["networks"])
        assert "solana:mainnet" not in network_ids
        assert "solana:devnet" not in network_ids
        assert (
            BUNDLED_MANIFEST["networkAliases"]["solana:mainnet"]
            == "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
        )

    def test_truncates_each_solana_genesis_hash_to_its_caip2_reference(self) -> None:
        """CAIP-2 caps the reference at 32 characters, so the identifier is a prefix.

        Cluster validation compares the *full* hash from ``getGenesisHash``, which only
        works if the two agree.
        """
        for network_id, network in BUNDLED_MANIFEST["networks"].items():
            if not network_id.startswith("solana:"):
                continue
            reference = network_id.removeprefix("solana:")
            assert len(reference) == 32
            assert network["genesisHash"][:32] == reference

    def test_gives_every_evm_network_a_chain_id_matching_its_caip2_reference(self) -> None:
        """SPEC §7.1."""
        for network_id, network in BUNDLED_MANIFEST["networks"].items():
            if not network_id.startswith("eip155:"):
                continue
            assert network["chainId"] == int(network_id.removeprefix("eip155:"))

    def test_covers_both_production_and_test_environments(self) -> None:
        environments = {
            network["environment"] for network in BUNDLED_MANIFEST["networks"].values()
        }
        assert environments == {"production", "test"}

    def test_names_a_trusted_key_this_build_actually_carries(self) -> None:
        assert BUNDLED_MANIFEST["signature"]["keyId"] in TRUSTED_MANIFEST_KEYS


class TestVerificationEdgeCases:
    def test_rejects_a_non_object(self) -> None:
        candidates: tuple[object, ...] = ("not a manifest", None, [])
        for candidate in candidates:
            result = verify_release_manifest(candidate, now_epoch_ms=NOW)
            assert not result.valid
            assert result.reason == "malformed"

    def test_reports_tampering_before_the_semantic_problem_it_introduced(self) -> None:
        """Confirms the normative check order: signature precedes the validity window."""
        inverted = dict(BUNDLED_MANIFEST)
        inverted["issuedAt"] = "2027-08-02T00:00:00Z"
        inverted["expiresAt"] = "2026-08-02T00:00:00Z"

        result = verify_release_manifest(inverted, now_epoch_ms=NOW)
        assert not result.valid
        assert result.reason == "signature-mismatch"

    def test_reports_missing_required_network_only_when_asked(self) -> None:
        required = verify_release_manifest(
            BUNDLED_MANIFEST, now_epoch_ms=NOW, required_networks=("eip155:1",)
        )
        assert not required.valid
        assert required.reason == "missing-required-network"

        # A caller-supplied manifest legitimately carries a single network, so the default
        # is to require nothing (SPEC §5.4's four-network rule binds the bundled manifest).
        assert verify_release_manifest(BUNDLED_MANIFEST, now_epoch_ms=NOW).valid

    def test_rejects_a_signature_value_of_the_wrong_length(self) -> None:
        wrong = {
            **BUNDLED_MANIFEST,
            "signature": {**BUNDLED_MANIFEST["signature"], "value": "c2hvcnQ="},
        }
        result = verify_release_manifest(wrong, now_epoch_ms=NOW)
        assert result.reason == "malformed-signature"

    def test_rejects_a_trusted_key_that_is_not_32_bytes(self) -> None:
        """Defends the key table itself: a truncated entry must fail closed."""
        result = verify_release_manifest(
            BUNDLED_MANIFEST,
            now_epoch_ms=NOW,
            trusted_keys={"tx402-release-1": "c2hvcnQ="},
        )
        assert result.reason == "unknown-key-id"


class TestStructureRejectedBeforeSignature:
    """These run ahead of signature verification, so a plain mutation reaches them."""

    @pytest.mark.parametrize(
        ("label", "override"),
        [
            ("release is not a string", {"release": 1}),
            ("issuedAt is not a string", {"issuedAt": 20260802}),
            ("networks is not an object", {"networks": []}),
            ("networkAliases is not an object", {"networkAliases": "none"}),
            ("signature is not an object", {"signature": "nope"}),
        ],
    )
    def test_rejects_malformed_structure(
        self, label: str, override: dict[str, Any]
    ) -> None:
        result = verify_release_manifest({**BUNDLED_MANIFEST, **override}, now_epoch_ms=NOW)
        assert result.reason == "malformed", label

    def test_rejects_a_manifest_missing_expires_at(self) -> None:
        without = {
            key: value for key, value in BUNDLED_MANIFEST.items() if key != "expiresAt"
        }
        assert verify_release_manifest(without, now_epoch_ms=NOW).reason == "malformed"


class TestContentCheckedAfterSignature:
    def test_accepts_a_correctly_signed_manifest(self) -> None:
        """Confirms the ephemeral-key harness works, so failures below are real."""
        assert verify_test_signed(sign_with_test_key(dict(BUNDLED_MANIFEST))).valid

    def test_rejects_a_manifest_declaring_no_networks(self) -> None:
        empty = sign_with_test_key(
            {**BUNDLED_MANIFEST, "networks": {}, "networkAliases": {}}
        )
        assert verify_test_signed(empty).reason == "malformed"

    def test_rejects_a_network_key_that_is_not_caip2(self) -> None:
        bad = sign_with_test_key(
            {
                **BUNDLED_MANIFEST,
                "networks": {"not a caip2 id": {"environment": "test"}},
                "networkAliases": {},
            }
        )
        assert verify_test_signed(bad).reason == "malformed"

    def test_rejects_a_network_entry_that_is_not_an_object(self) -> None:
        bad = sign_with_test_key(
            {
                **BUNDLED_MANIFEST,
                "networks": {"eip155:8453": "not an object"},
                "networkAliases": {},
            }
        )
        assert verify_test_signed(bad).reason == "malformed"

    def test_rejects_a_timestamp_without_an_explicit_utc_z(self) -> None:
        """A local offset would let two hosts disagree about whether it has expired."""
        local = sign_with_test_key(
            {**BUNDLED_MANIFEST, "issuedAt": "2026-08-02T00:00:00+02:00"}
        )
        assert verify_test_signed(local).reason == "malformed"

    def test_rejects_a_timestamp_that_ends_in_z_but_is_not_a_date(self) -> None:
        nonsense = sign_with_test_key({**BUNDLED_MANIFEST, "expiresAt": "not-a-dateZ"})
        assert verify_test_signed(nonsense).reason == "malformed"

    def test_rejects_an_inverted_validity_window(self) -> None:
        inverted = sign_with_test_key(
            {
                **BUNDLED_MANIFEST,
                "issuedAt": "2027-08-02T00:00:00Z",
                "expiresAt": "2026-08-02T00:00:00Z",
            }
        )
        assert verify_test_signed(inverted).reason == "invalid-validity-window"

    def test_rejects_an_alias_whose_target_is_not_a_string(self) -> None:
        bad = sign_with_test_key(
            {**BUNDLED_MANIFEST, "networkAliases": {"solana:mainnet": 42}}
        )
        assert verify_test_signed(bad).reason == "alias-target-unknown"


class TestAssertValidReleaseManifest:
    def test_returns_the_manifest_when_it_verifies(self) -> None:
        returned = assert_valid_release_manifest(
            BUNDLED_MANIFEST, context=CONTEXT, now_epoch_ms=NOW
        )
        assert returned is BUNDLED_MANIFEST

    def test_raises_configuration_error_carrying_the_reason(self) -> None:
        """SPEC §5.4 requires manifest failure to prevent client construction.

        The reason has to survive into ``details``: someone debugging a failed construction
        needs to know it was expiry, not a bad key.
        """
        expired_at = 1830297600000.0  # 2028-01-01T00:00:00Z
        with pytest.raises(ConfigurationError) as raised:
            assert_valid_release_manifest(
                BUNDLED_MANIFEST, context=CONTEXT, now_epoch_ms=expired_at
            )
        assert raised.value.code == "TX402_CONFIG_INVALID"
        assert raised.value.details["configPath"] == "manifest"
        assert raised.value.details["reason"] == "expired"


class TestRequireNetwork:
    def test_resolves_an_alias_to_its_canonical_identifier(self) -> None:
        resolved = require_network(BUNDLED_MANIFEST, "solana:mainnet", CONTEXT)
        assert resolved == "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

    def test_returns_a_canonical_identifier_unchanged(self) -> None:
        assert require_network(BUNDLED_MANIFEST, "eip155:8453", CONTEXT) == "eip155:8453"

    def test_raises_naming_the_config_path_that_carried_the_bad_value(self) -> None:
        with pytest.raises(ConfigurationError) as raised:
            require_network(
                BUNDLED_MANIFEST, "eip155:1", CONTEXT, "routing.prefer_networks"
            )
        assert raised.value.details["configPath"] == "routing.prefer_networks"
        assert raised.value.details["reason"] == "unknown-network"


class TestResolveNetwork:
    def test_ignores_an_alias_whose_target_the_manifest_does_not_declare(self) -> None:
        """Defence in depth — verification already rejects a dangling alias."""
        dangling = {
            **BUNDLED_MANIFEST,
            "networkAliases": {"solana:testnet": "solana:nowhere"},
        }
        assert resolve_network(dangling, "solana:testnet").reason == "unknown-network"
