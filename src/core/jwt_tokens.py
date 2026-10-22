"""
src/core/jwt_tokens.py

Reading a JSON Web Token (JWT) and producing the deliberately invalid variants
that test 1.2 presents to a target to confirm it refuses them.

A JWT is three base64url segments joined by dots: a header, a payload (the
claims) and a signature over the first two. A target that keeps the guarantee
recomputes the signature and refuses any token whose signature does not match.
The variants here are the ones that need no key, so they are the test for the
one failure that matters most: a server that does not verify the signature at
all. Each is built to be rejected; presenting it and seeing a `2xx` is the
finding (test 1.2, docs/project/test-review/group-c.md). None of this signs
anything: the variants that would need the signing or the public key (an
expired `exp`, algorithm confusion) cannot be built without key material the
target does not give us, and the test reports them as not verifiable rather
than faking them.

This module reads and rewrites tokens; it does not send them and holds no test
logic.

Dependency rule: imports only from the standard library.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from enum import StrEnum


class JwtVariant(StrEnum):
    """
    A way a token is degraded, for the result and the finding.

    ALG_NONE          -- the header's algorithm set to `none` and the signature
                         emptied: the token claims to need no signature.
    TAMPERED_PAYLOAD  -- a claim changed, the original signature kept: the
                         payload no longer matches what was signed.
    STRIPPED_SIGNATURE -- the signature segment emptied: only header and payload
                         are sent.
    """

    ALG_NONE = "ALG_NONE"
    TAMPERED_PAYLOAD = "TAMPERED_PAYLOAD"
    STRIPPED_SIGNATURE = "STRIPPED_SIGNATURE"


@dataclass(frozen=True)
class JwtView:
    """A decoded JWT: its three raw segments and the parsed header and claims."""

    header_segment: str
    payload_segment: str
    signature_segment: str
    header: dict[str, object]
    claims: dict[str, object]


def decode(token: str) -> JwtView | None:
    """
    Read a JWT, or return None when the string is not one.

    Args:
        token: The credential as the target issued it.

    Returns:
        A JwtView when the string is three dot-separated segments whose first
        two are base64url-encoded JSON objects; None otherwise (an opaque
        token, such as Forgejo's sha1 API token).
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = _decode_segment(parts[0])
        claims = _decode_segment(parts[1])
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    return JwtView(
        header_segment=parts[0],
        payload_segment=parts[1],
        signature_segment=parts[2],
        header=header,
        claims=claims,
    )


def with_alg_none(view: JwtView) -> str:
    """
    The token with its algorithm set to `none` and an empty signature.

    A library that honours `alg: none` accepts it without checking anything,
    which is the historical JWT bypass (CVE-2015-9235). A target that keeps the
    guarantee refuses it.

    Args:
        view: The decoded genuine token.

    Returns:
        The variant, ready to send.
    """
    header = dict(view.header)
    header["alg"] = "none"
    return f"{_encode_segment(header)}.{view.payload_segment}."


def with_tampered_payload(view: JwtView) -> str:
    """
    The token with one claim changed and the original signature kept.

    The signature no longer matches the payload, so a target that verifies it
    refuses the token; one that reads the claims without verifying accepts the
    changed identity. The claim changed is the subject (`sub`) or, failing
    that, the first claim, appended with a marker so the value is certainly
    different without needing to know its type.

    Args:
        view: The decoded genuine token.

    Returns:
        The variant, ready to send.
    """
    claims = dict(view.claims)
    key = "sub" if "sub" in claims else next(iter(claims), "sub")
    claims[key] = f"{claims.get(key, '')}{_TAMPER_MARKER}"
    return f"{view.header_segment}.{_encode_segment(claims)}.{view.signature_segment}"


def stripped_signature(view: JwtView) -> str:
    """
    The token with its signature segment emptied.

    Only the header and the payload are sent, with a trailing dot. A target
    that treats a missing signature as an implicit `alg: none`, or that does
    not require one, accepts it.

    Args:
        view: The decoded genuine token.

    Returns:
        The variant, ready to send.
    """
    return f"{view.header_segment}.{view.payload_segment}."


# Appended to a claim to make its value certainly different from the original.
_TAMPER_MARKER: str = "-zqxv"


def _decode_segment(segment: str) -> object:
    """Base64url-decode one segment and parse it as JSON (padding restored)."""
    padded = segment + "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode(padded)
    return json.loads(raw)


def _encode_segment(value: dict[str, object]) -> str:
    """Encode a header or payload back to a base64url segment, without padding."""
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")
