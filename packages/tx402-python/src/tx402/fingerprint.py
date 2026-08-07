"""Secret-free request fingerprinting (SEC-009)."""

from __future__ import annotations

import hashlib
import posixpath
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

from tx402.canonical_json import canonicalize_json

REQUEST_FINGERPRINT_DOMAIN = "tx402-request-fingerprint-v1\n"


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def normalize_fingerprint_url(value: str) -> str:
    """Normalize a URL while dropping secret user-info and the non-transmitted fragment."""
    parsed = urlsplit(value)
    if not parsed.scheme or parsed.hostname is None:
        raise ValueError("Fingerprint URL must be absolute")
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    port = parsed.port
    if port is not None and not (
        (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    ):
        hostname = f"{hostname}:{port}"
    path = parsed.path or "/"
    trailing = path.endswith("/")
    path = posixpath.normpath(path)
    if not path.startswith("/"):
        path = f"/{path}"
    if trailing and path != "/":
        path = f"{path}/"
    path = quote(path, safe="/%:@-._~!$&'()*+,;=")
    return urlunsplit(SplitResult(scheme, hostname, path, parsed.query, ""))


def digest_request_body(body: str | bytes | None) -> str:
    """Digest raw request-body bytes; ``None`` is the empty byte sequence."""
    raw = b"" if body is None else body.encode("utf-8") if isinstance(body, str) else body
    return _sha256(raw)


def fingerprint_request(
    *, method: str, url: str, body: str | bytes | None, challenge_hash: str
) -> str:
    """Bind method, normalized URL, body digest, and challenge hash."""
    document = {
        "bodyHash": digest_request_body(body),
        "challengeHash": challenge_hash,
        "method": method.upper(),
        "url": normalize_fingerprint_url(url),
    }
    payload = f"{REQUEST_FINGERPRINT_DOMAIN}{canonicalize_json(document)}".encode()
    return _sha256(payload)
