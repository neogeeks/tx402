"""Public keys this build trusts to sign a release manifest (SPEC §5.4).

Compiled in, deliberately. A key shipped *alongside* a manifest would authenticate nothing
— an attacker who can replace the manifest can replace an adjacent key file just as easily.
Trust has to terminate in the package itself, and this module is where it does.

There is no remote key fetch in v0.1, and there will not be one without a new threat model:
fetching a key at construction time would turn an offline integrity check into a network
dependency on tx402 infrastructure, which SPEC §13.1 rules out architecturally.

Rotation adds an entry rather than replacing one, so manifests signed by the previous key
keep verifying for their remaining lifetime. A key is removed only once every manifest it
signed has expired.

Mirrors ``packages/tx402/src/core/trusted-keys.ts``.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

__all__ = ["MANIFEST_SIGNING_DOMAIN", "TRUSTED_MANIFEST_KEYS"]

#: keyId to standard-alphabet base64 of the raw 32-byte Ed25519 public key.
TRUSTED_MANIFEST_KEYS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "tx402-release-1": "pFKQxLkGxeV4ZEsRFapcsfe0lulPBOfpnGygqazrgDY=",
        "tx402-release-2": "8wcL7EWGIMVSK75rZ8lnGIwBYiJKQQMsLllpGkaoLt4=",
    }
)

#: Domain separation prefix for manifest signatures (ADR-012).
#:
#: Prepended to the canonical bytes so a signature over a tx402 manifest can never be
#: replayed as a signature over a different document the same key signs. The ``/v1`` suffix
#: means changing the envelope invalidates old signatures instead of silently
#: reinterpreting them.
MANIFEST_SIGNING_DOMAIN: Final = "tx402-release-manifest/v1\n"
