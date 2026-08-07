"""The optional private-key convenience signer (SEC-001, SPEC §7.1).

This module is the one place in the package that holds key material, so it is tested for
what it must *not* do as much as for what it does: the key must not be reachable by
attribute access, must not appear in any serialization, and must not be quoted back in a
validation error.
"""

from __future__ import annotations

import dataclasses
import json
import pickle
from types import MappingProxyType
from typing import Any

import pytest

from tx402.evm import EvmSignerPresentation, EvmTypedDataRequest
from tx402.signers import PrivateKeyEvmSigner, private_key_to_evm_signer

# A throwaway key generated for this test alone. It holds nothing on any chain.
KEY = "0xa11ce00000000000000000000000000000000000000000000000000000000001"


def request() -> EvmTypedDataRequest:
    return EvmTypedDataRequest(
        domain=MappingProxyType(
            {
                "name": "USD Coin",
                "version": "2",
                "chainId": 8453,
                "verifyingContract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            }
        ),
        types=MappingProxyType(
            {
                "TransferWithAuthorization": (
                    MappingProxyType({"name": "from", "type": "address"}),
                    MappingProxyType({"name": "to", "type": "address"}),
                    MappingProxyType({"name": "value", "type": "uint256"}),
                    MappingProxyType({"name": "validAfter", "type": "uint256"}),
                    MappingProxyType({"name": "validBefore", "type": "uint256"}),
                    MappingProxyType({"name": "nonce", "type": "bytes32"}),
                )
            }
        ),
        primary_type="TransferWithAuthorization",
        message=MappingProxyType(
            {
                "from": "0x0000000000000000000000000000000000000001",
                "to": "0x1234567890AbcdEF1234567890aBcdef12345678",
                "value": 50000,
                "validAfter": 0,
                "validBefore": 1_785_715_260,
                "nonce": "0x" + "11" * 32,
            }
        ),
        presentation=EvmSignerPresentation(
            network="eip155:8453",
            asset_id="eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            asset_symbol="USDC",
            amount_atomic="50000",
            amount_decimal="0.050000",
            recipient="0x1234567890AbcdEF1234567890aBcdef12345678",
            resource_host="merchant.test",
            domain_name="USD Coin",
            expires_at="2026-08-04T00:01:00Z",
            request_hash="sha256:" + "0" * 64,
        ),
    )


class TestSigning:
    def test_derives_a_stable_address_from_the_key(self) -> None:
        signer = private_key_to_evm_signer(KEY)
        assert signer.kind == "evm"
        assert signer.get_address().startswith("0x")
        assert len(signer.get_address()) == 42
        # Deterministic: the same key is the same account every time.
        assert signer.get_address() == private_key_to_evm_signer(KEY).get_address()

    def test_produces_a_65_byte_secp256k1_signature(self) -> None:
        signature = private_key_to_evm_signer(KEY).sign_typed_data(request())
        assert isinstance(signature, bytes)
        # r (32) + s (32) + v (1). The EVM adapter rejects anything else.
        assert len(signature) == 65

    def test_signing_is_deterministic_for_the_same_message(self) -> None:
        """RFC 6979 deterministic ECDSA: no nonce reuse risk from a bad RNG."""
        first = private_key_to_evm_signer(KEY).sign_typed_data(request())
        second = private_key_to_evm_signer(KEY).sign_typed_data(request())
        assert first == second

    def test_the_presentation_is_not_signed_only_the_eip712_structure_is(self) -> None:
        """SPEC §6.6's presentation is for a human to read, not for the chain to verify."""
        baseline = request()
        altered = dataclasses.replace(
            baseline,
            presentation=dataclasses.replace(baseline.presentation, asset_symbol="NOTUSDC"),
        )
        signer = private_key_to_evm_signer(KEY)
        assert signer.sign_typed_data(altered) == signer.sign_typed_data(baseline)


class TestKeyIsNotReachable:
    def test_the_key_is_not_an_attribute(self) -> None:
        signer = private_key_to_evm_signer(KEY)
        assert not any(
            KEY in str(getattr(signer, name, "")) for name in PrivateKeyEvmSigner.__slots__
        )
        assert not hasattr(signer, "private_key")
        assert not hasattr(signer, "_private_key")

    def test_repr_renders_a_redacted_placeholder(self) -> None:
        signer = private_key_to_evm_signer(KEY)
        rendered = repr(signer)
        assert rendered == f"PrivateKeyEvmSigner(evm:{signer.get_address()})"
        assert KEY not in rendered
        assert KEY[2:] not in rendered

    def test_it_cannot_be_pickled_into_another_process(self) -> None:
        with pytest.raises(TypeError, match="cannot be pickled"):
            pickle.dumps(private_key_to_evm_signer(KEY))


class TestValidation:
    @pytest.mark.parametrize(
        "value",
        [
            "not-a-key",
            "a11ce00000000000000000000000000000000000000000000000000000000001",
            "0xa11ce",
            "0x" + "z" * 64,
            "",
        ],
    )
    def test_rejects_anything_that_is_not_32_byte_prefixed_hex(self, value: str) -> None:
        with pytest.raises(ValueError, match="0x-prefixed 32-byte hex"):
            private_key_to_evm_signer(value)

    def test_a_validation_error_never_quotes_the_rejected_value(self) -> None:
        secret = "0x" + "beef" * 15  # wrong length, but still plausibly a real key
        with pytest.raises(ValueError, match="32-byte hex") as raised:
            private_key_to_evm_signer(secret)
        assert secret not in str(raised.value)
        assert "beef" not in str(raised.value)

    def test_rejects_a_non_string(self) -> None:
        with pytest.raises(ValueError, match="0x-prefixed 32-byte hex"):
            private_key_to_evm_signer(b"\x01" * 32)  # type: ignore[arg-type]


def test_importing_tx402_does_not_import_this_module() -> None:
    """SEC-001: nothing in the core API may reach the private-key adapter.

    A core install has no `eth_account`, so an accidental import here would break
    `import tx402` for a user who installed exactly what the README told them to.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, tx402; "
            "assert 'tx402.signers' not in sys.modules, 'tx402.signers was imported'; "
            "assert 'eth_account' not in sys.modules, 'eth_account was imported'; "
            "print('clean')",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "clean" in result.stdout


# --- The Solana counterpart (SEC-001, SPEC §7.2) ----------------------------------------

# A throwaway keypair derived from a fixed seed for this test alone. It holds nothing on
# any cluster, and the same bytes appear in the TypeScript suite so the two languages are
# proven to derive the same address and the same signature from one input.
SOLANA_KEYPAIR = [
    14, 200, 93, 200, 99, 239, 157, 82, 111, 247, 30, 2, 138, 61, 188, 29,
    138, 92, 85, 5, 220, 150, 210, 158, 61, 73, 122, 94, 137, 34, 216, 241,
    200, 103, 77, 26, 108, 138, 48, 143, 33, 107, 244, 199, 17, 251, 21, 8,
    84, 91, 77, 73, 60, 57, 114, 66, 52, 8, 179, 238, 103, 132, 135, 46,
]  # fmt: skip
SOLANA_ADDRESS = "EVHuBQEV9EL3kVzBndVQTKvhdHbAdNBkMfJBteUyhU13"


def _svm_request(message: bytes, **overrides: object) -> Any:
    """A structural stand-in for :class:`tx402.solana.SolanaSignRequest`.

    Built here rather than imported so this module does not require the ``svm`` extra to be
    collected. The adapter reads ``message_bytes`` and nothing else, which is the property
    under test.
    """
    fields: dict[str, object] = {
        "message_bytes": message,
        "transaction_bytes": b"\xff" * 16,
        "presentation": object(),
    }
    fields.update(overrides)
    return type("SvmRequestStub", (), fields)()


class TestSolanaSigning:
    def test_accepts_the_json_array_solana_keygen_writes(self) -> None:
        from tx402.signers import keypair_to_solana_signer

        signer = keypair_to_solana_signer(json.dumps(SOLANA_KEYPAIR))
        assert signer.get_public_key() == SOLANA_ADDRESS

    def test_accepts_raw_bytes_and_a_sequence_identically(self) -> None:
        from tx402.signers import keypair_to_solana_signer

        assert (
            keypair_to_solana_signer(bytes(SOLANA_KEYPAIR)).get_public_key()
            == keypair_to_solana_signer(SOLANA_KEYPAIR).get_public_key()
            == SOLANA_ADDRESS
        )

    def test_produces_a_64_byte_ed25519_signature(self) -> None:
        from tx402.signers import keypair_to_solana_signer

        signer = keypair_to_solana_signer(SOLANA_KEYPAIR)
        assert len(signer.sign_transaction(_svm_request(b"\x80hello"))) == 64

    def test_signs_message_bytes_and_nothing_else(self) -> None:
        """``transaction_bytes`` and ``presentation`` are context, not signing input.

        Ed25519 is deterministic, so signing the same ``message_bytes`` twice under two
        different surrounding requests must yield identical bytes. If the adapter ever
        folded either field in, these two signatures would diverge.
        """
        from tx402.signers import keypair_to_solana_signer

        signer = keypair_to_solana_signer(SOLANA_KEYPAIR)
        first = _svm_request(b"\x80same message")
        second = _svm_request(
            b"\x80same message",
            transaction_bytes=b"\x00" * 32,
            presentation={"different": True},
        )
        assert signer.sign_transaction(first) == signer.sign_transaction(second)


class TestSolanaKeyIsNotReachable:
    def test_the_keypair_is_not_an_attribute(self) -> None:
        from tx402.signers import keypair_to_solana_signer

        signer = keypair_to_solana_signer(SOLANA_KEYPAIR)
        assert not hasattr(signer, "keypair")
        assert not hasattr(signer, "_keypair")
        assert set(type(signer).__slots__) == {"_public_key", "_sign"}

    def test_repr_renders_a_redacted_placeholder(self) -> None:
        from tx402.signers import keypair_to_solana_signer

        rendered = repr(keypair_to_solana_signer(SOLANA_KEYPAIR))
        assert rendered == f"KeypairSolanaSigner(solana:{SOLANA_ADDRESS})"
        assert "14" not in rendered or str(SOLANA_KEYPAIR[:4]) not in rendered

    def test_it_cannot_be_pickled_into_another_process(self) -> None:
        from tx402.signers import keypair_to_solana_signer

        with pytest.raises(TypeError, match="cannot be pickled"):
            pickle.dumps(keypair_to_solana_signer(SOLANA_KEYPAIR))


class TestSolanaValidation:
    @pytest.mark.parametrize(
        "value",
        [
            None,
            12345,
            "not json at all",
            "{}",
            "[1, 2, 3]",
            json.dumps([0] * 63),
            json.dumps([0] * 65),
            json.dumps([999] * 64),
            json.dumps([-1] * 64),
        ],
    )
    def test_rejects_anything_that_is_not_64_keypair_bytes(self, value: object) -> None:
        from tx402.signers import keypair_to_solana_signer

        with pytest.raises(ValueError, match="keypair_to_solana_signer"):
            keypair_to_solana_signer(value)  # type: ignore[arg-type]

    def test_a_validation_error_never_quotes_the_rejected_value(self) -> None:
        """A malformed key is still a key. Echoing it is how it reaches a traceback."""
        from tx402.signers import keypair_to_solana_signer

        secret = json.dumps([7] * 63)
        with pytest.raises(ValueError, match="64 keypair bytes") as raised:
            keypair_to_solana_signer(secret)
        assert secret not in str(raised.value)
        assert "7, 7, 7" not in str(raised.value)
