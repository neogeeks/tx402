"""Optional private-key convenience signer adapters.

Port of ``packages/tx402/src/signers/index.ts``. Deliberately a module nothing else in
the package imports: per SEC-001 the primary client configuration accepts **signer
abstractions only** and never a raw private key, so nothing in the core API can reach this
code. A caller has to ``from tx402.signers import private_key_to_evm_signer`` by name,
which is what makes the choice explicit and auditable in a diff.

**Use an external signer if you can.** SPEC §9.1 lists prompt injection extracting a
wallet key as a live threat for exactly the autonomous agents this SDK targets, and a key
held in process memory is a key an in-process compromise can read. A KMS, a hardware
wallet, or a remote signing service implements the same :class:`~tx402.evm.EvmSigner`
protocol and keeps the key outside the blast radius. This adapter exists for development
and for small, dedicated, low-balance wallets.

The key is captured in a closure and is never stored on the returned object, never
serialized, and never logged. ``__repr__`` is overridden so that a signer accidentally
passed to a logger renders as a redacted placeholder rather than as an object holding an
account.

Example::

    import os
    from tx402.signers import keypair_to_solana_signer, private_key_to_evm_signer

    evm = private_key_to_evm_signer(os.environ["TX402_DEV_PRIVATE_KEY"])
    solana = keypair_to_solana_signer(os.environ["TX402_DEV_SOLANA_KEYPAIR"])
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Final, Literal

from tx402.evm import EvmTypedDataRequest

if TYPE_CHECKING:
    # `tx402.solana` imports `solders` at module scope, so importing it here at runtime
    # would make `tx402.signers` — and therefore `private_key_to_evm_signer` — require the
    # `svm` extra. A caller who installed `tx402[evm]` must be able to import this module.
    from tx402.solana import SolanaSignRequest

__all__ = [
    "KeypairSolanaSigner",
    "PrivateKeyEvmSigner",
    "keypair_to_solana_signer",
    "private_key_to_evm_signer",
]

_PRIVATE_KEY: Final = re.compile(r"^0x[0-9a-fA-F]{64}$")

#: Bytes in a Solana keypair file: a 32-byte seed followed by the 32-byte public key.
_SOLANA_KEYPAIR_BYTES: Final = 64


class PrivateKeyEvmSigner:
    """An :class:`~tx402.evm.EvmSigner` backed by a raw secp256k1 key.

    The key lives in ``_sign``'s closure. It is not an attribute, so it cannot be reached
    by attribute access, by ``vars()``, or by a serializer walking the object.
    """

    kind: Literal["evm"] = "evm"

    __slots__ = ("_address", "_sign")

    def __init__(self, private_key: str) -> None:
        if not isinstance(private_key, str) or not _PRIVATE_KEY.match(private_key):
            # Validated here rather than by the chain library, whose own validation error
            # tends to quote its input — which is how a key reaches a traceback.
            raise ValueError(
                "private_key_to_evm_signer expects a 0x-prefixed 32-byte hex private key"
            )

        # Imported lazily so the core install never loads a chain library: `import tx402`
        # must not require the `evm` extra, and `tests/test_package_contract.py` asserts it.
        from eth_account import Account
        from eth_account.messages import encode_typed_data

        account = Account.from_key(private_key)
        self._address: str = str(account.address)

        def sign(request: EvmTypedDataRequest) -> bytes:
            # `presentation` is tx402's human-readable summary (SPEC §6.6). eth-account
            # signs the EIP-712 structure only, so it is deliberately not forwarded.
            encoded = encode_typed_data(
                full_message={
                    "domain": dict(request.domain),
                    "types": {
                        name: [dict(field) for field in fields]
                        for name, fields in request.types.items()
                    },
                    "primaryType": request.primary_type,
                    "message": dict(request.message),
                }
            )
            # Returned as raw bytes rather than as a hex string: `HexBytes` is a `bytes`
            # subclass, so the adapter's `isinstance(..., bytes)` branch accepts it
            # directly and no prefix convention has to be agreed on twice.
            return bytes(account.sign_message(encoded).signature)

        self._sign = sign

    def get_address(self) -> str:
        return self._address

    def sign_typed_data(self, request: EvmTypedDataRequest) -> bytes | str:
        return self._sign(request)

    def __repr__(self) -> str:
        return f"PrivateKeyEvmSigner(evm:{self._address})"

    def __reduce__(self) -> Any:
        # Pickling would be a second route to serializing the closure. Refused outright:
        # there is no legitimate reason to send a live signer to another process.
        raise TypeError("a tx402 signer cannot be pickled")


def private_key_to_evm_signer(private_key: str) -> PrivateKeyEvmSigner:
    """Wraps a raw secp256k1 private key as an :class:`~tx402.evm.EvmSigner`.

    :param private_key: 32-byte hex, ``0x``-prefixed. Never logged, and rejected before
        ``eth_account`` sees it if it is malformed.
    """
    return PrivateKeyEvmSigner(private_key)


def _solana_keypair_bytes(keypair: str | bytes | Sequence[int]) -> bytes:
    """Normalizes the shapes a Solana keypair arrives in into its 64 raw bytes.

    ``solana-keygen`` writes a JSON array of byte values to ``~/.config/solana/id.json``, so
    that string is what a caller actually has in hand and what an environment variable
    actually carries. Parsing it here keeps the mistakes in one place.

    No error message quotes the input. A malformed key is still a key, and a validation
    message that echoes it is how key material reaches a traceback.
    """
    values: bytes | Sequence[int]
    if isinstance(keypair, str):
        try:
            parsed = json.loads(keypair)
        except ValueError:
            raise ValueError(
                "keypair_to_solana_signer expects a JSON array of 64 keypair bytes, as "
                "written by `solana-keygen` — it could not be parsed as JSON"
            ) from None
        if not isinstance(parsed, list):
            raise ValueError(
                "keypair_to_solana_signer expects a JSON array of 64 keypair bytes"
            )
        values = parsed
    elif isinstance(keypair, (bytes, bytearray, list, tuple)):
        values = keypair
    else:
        # Reached when a caller passes an unset ``os.environ.get(...)``. Without this branch
        # ``len()`` raises a bare ``TypeError`` that says nothing about what was expected.
        raise ValueError(
            "keypair_to_solana_signer expects 64 keypair bytes or the JSON array string "
            "`solana-keygen` writes, and received neither"
        )

    if len(values) != _SOLANA_KEYPAIR_BYTES:
        raise ValueError(
            f"keypair_to_solana_signer expects {_SOLANA_KEYPAIR_BYTES} keypair bytes, "
            f"received {len(values)}"
        )
    if not all(isinstance(value, int) and 0 <= value <= 255 for value in values):
        raise ValueError(
            "keypair_to_solana_signer expects keypair bytes in the range 0-255"
        )

    return bytes(values)


class KeypairSolanaSigner:
    """A :class:`~tx402.solana.SolanaSigner` backed by a raw Ed25519 keypair.

    The keypair lives in ``_sign``'s closure and in the ``solders`` object it captures. It
    is not an attribute, so it cannot be reached by attribute access, by ``vars()``, or by a
    serializer walking the object.
    """

    kind: Literal["solana"] = "solana"

    __slots__ = ("_public_key", "_sign")

    def __init__(self, keypair: str | bytes | Sequence[int]) -> None:
        raw = _solana_keypair_bytes(keypair)

        # Imported lazily so the core install never loads a chain library, exactly as the
        # EVM adapter does: `import tx402` must not require the `svm` extra.
        from solders.keypair import Keypair

        inner = Keypair.from_bytes(raw)
        self._public_key: str = str(inner.pubkey())

        def sign(request: SolanaSignRequest) -> bytes:
            # Only `message_bytes` is signed. `transaction_bytes` and `presentation` exist
            # so a hardware or KMS adapter can display and independently decode the same
            # transaction; signing anything else would sign something other than what the
            # runtime verifies.
            return bytes(inner.sign_message(request.message_bytes))

        self._sign = sign

    def get_public_key(self) -> str:
        return self._public_key

    def sign_transaction(self, request: SolanaSignRequest) -> bytes:
        return self._sign(request)

    def __repr__(self) -> str:
        return f"KeypairSolanaSigner(solana:{self._public_key})"

    def __reduce__(self) -> Any:
        raise TypeError("a tx402 signer cannot be pickled")


def keypair_to_solana_signer(keypair: str | bytes | Sequence[int]) -> KeypairSolanaSigner:
    """Wraps a raw Ed25519 keypair as a :class:`~tx402.solana.SolanaSigner`.

    The Solana counterpart to :func:`private_key_to_evm_signer`, and it carries the same
    warning: prefer an external signer.

    :param keypair: The 64 bytes of a Solana keypair, or the JSON array string that
        ``solana-keygen`` writes. Never logged, and rejected before ``solders`` sees it if
        it is malformed.
    """
    return KeypairSolanaSigner(keypair)
