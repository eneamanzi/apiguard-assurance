"""
src/tests/helpers/jwt_forge.py

Pure JWT manipulation utility for cryptographic validation tests.

Responsibility
--------------
Provides functions to inspect, decode, and forge malformed JWT tokens for use
in security tests that verify server-side JWT validation (test 1.2, test 1.3).
All functions are pure: they take strings and return strings, with no HTTP
calls, no TestContext writes, and no side effects.

JWT structure recap
-------------------
A JWT is three Base64url-encoded segments separated by dots:
    {header_b64}.{payload_b64}.{signature_b64}

Base64url differs from standard Base64 in two ways:
    - '+' is replaced with '-'
    - '/' is replaced with '_'
    - Padding ('=') is stripped when encoding, must be re-added when decoding

Attack surface covered
----------------------
This module supports the attacks defined in methodology section 1.2:

    alg:none        -- Server must reject tokens declaring no algorithm.
    Tampered payload -- Server must re-verify the signature after any claim
                        change; a valid signature on a modified payload is
                        cryptographically invalid.
    Signature strip  -- Removing the signature segment must be treated as
                        equivalent to alg:none, not as a valid token.
    Expired token    -- Server must compare exp claim against current UTC time.
    Key confusion    -- RS256-to-HS256 attack: signing a token with HS256
                        using the RSA public key as HMAC secret. Requires the
                        public key PEM, obtainable from /.well-known/jwks.json.

What this module does NOT do
-----------------------------
    - Generate valid signed tokens (no private keys are available).
    - Validate signatures (that is the server's job, not the tester's).
    - Make HTTP requests.

Dependency rule
---------------
This module imports only from stdlib. It must never import from src.core,
src.tests, or any third-party library. The only external dependency is the
'cryptography' package for the key confusion attack, imported locally inside
forge_hs256_key_confusion() to keep it optional and scoped.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, cast

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Separator character in JWT compact serialization (RFC 7519 Section 3).
_JWT_SEPARATOR: str = "."

# Expected number of segments in a well-formed JWT.
_JWT_SEGMENT_COUNT: int = 3

# Header segment index.
_JWT_HEADER_INDEX: int = 0

# Payload segment index.
_JWT_PAYLOAD_INDEX: int = 1

# Signature segment index.
_JWT_SIGNATURE_INDEX: int = 2

# alg claim key in JWT header.
_CLAIM_ALG: str = "alg"

# typ claim key in JWT header.
_CLAIM_TYP: str = "typ"

# exp claim key in JWT payload (Unix timestamp, RFC 7519 Section 4.1.4).
_CLAIM_EXP: str = "exp"

# Value used in the alg:none attack (RFC 7519 Section 6).
_ALG_NONE: str = "none"

# Algorithm identifier for HMAC-SHA256 (RFC 7518 Section 3.2).
_ALG_HS256: str = "HS256"

# Standard JWT type declaration.
_TYP_JWT: str = "JWT"


# ---------------------------------------------------------------------------
# Inspection helpers
# ---------------------------------------------------------------------------


def is_jwt_format(token: str) -> bool:
    """
    Return True if the token string has the three-segment JWT structure.

    Does not verify the signature or validate any claims. A token that passes
    this check may still be invalid, expired, or forged. The check exists
    only to determine whether JWT-specific attack functions are applicable
    to a given token (Forgejo uses opaque tokens for most operations).

    Args:
        token: The token string to inspect.

    Returns:
        True if the token contains exactly two dot separators and each
        segment is non-empty. False otherwise.
    """
    if not token or not isinstance(token, str):
        return False

    segments = token.split(_JWT_SEPARATOR)
    if len(segments) != _JWT_SEGMENT_COUNT:
        return False

    # Header and payload must be non-empty. The signature segment may be
    # empty in the alg:none attack case — that is precisely the malformed
    # structure the forge functions produce and the tests submit.
    return bool(segments[_JWT_HEADER_INDEX]) and bool(segments[_JWT_PAYLOAD_INDEX])


def decode_header(token: str) -> dict[str, Any]:
    """
    Decode and return the JWT header as a Python dict.

    Does not verify the signature. Raises ValueError if the token is not in
    JWT format or if the header segment cannot be decoded as JSON.

    Args:
        token: A JWT string in compact serialization format.

    Returns:
        Decoded header dict (e.g. {"alg": "RS256", "typ": "JWT"}).

    Raises:
        ValueError: If the token is not in JWT format or the header is not
                    valid Base64url-encoded JSON.
    """
    _require_jwt_format(token)
    header_b64 = token.split(_JWT_SEPARATOR)[_JWT_HEADER_INDEX]
    return cast(dict[str, Any], json.loads(_b64url_decode(header_b64)))


def decode_payload(token: str) -> dict[str, Any]:
    """
    Decode and return the JWT payload as a Python dict.

    Does not verify the signature. Raises ValueError if the token is not in
    JWT format or if the payload segment cannot be decoded as JSON.

    Args:
        token: A JWT string in compact serialization format.

    Returns:
        Decoded payload dict (e.g. {"sub": "1", "exp": 1700000000}).

    Raises:
        ValueError: If the token is not in JWT format or the payload is not
                    valid Base64url-encoded JSON.
    """
    _require_jwt_format(token)
    payload_b64 = token.split(_JWT_SEPARATOR)[_JWT_PAYLOAD_INDEX]
    return cast(dict[str, Any], json.loads(_b64url_decode(payload_b64)))


# ---------------------------------------------------------------------------
# Forge functions — each returns a malformed JWT string
# ---------------------------------------------------------------------------


def forge_alg_none(token: str) -> str:
    """
    Return a JWT with the 'alg' header set to 'none' and an empty signature.

    This attack (CVE-2015-9235) exploits libraries that accept unsigned tokens
    when the algorithm is declared as 'none'. A secure server must reject
    this token with 401 regardless of the payload's validity.

    The payload is preserved unchanged from the original token. Only the
    header is modified to declare alg=none and the signature is removed.

    Args:
        token: A valid JWT string to use as the base. The payload is copied
               as-is; only the header is rewritten.

    Returns:
        JWT string with alg=none header, original payload, and empty
        signature: '{header}.{payload}.'

    Raises:
        ValueError: If the token is not in JWT format.
    """
    _require_jwt_format(token)
    segments = token.split(_JWT_SEPARATOR)

    new_header = {_CLAIM_ALG: _ALG_NONE, _CLAIM_TYP: _TYP_JWT}
    new_header_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")))

    original_payload_b64 = segments[_JWT_PAYLOAD_INDEX]

    return f"{new_header_b64}{_JWT_SEPARATOR}{original_payload_b64}{_JWT_SEPARATOR}"


def forge_tampered_payload(token: str, claim: str, new_value: Any) -> str:  # noqa: ANN401
    """
    Return a JWT with one payload claim replaced, keeping the original signature.

    The signature is no longer valid for the new payload. A secure server must
    detect the mismatch and reject the token with 401.

    This tests whether the server actually re-verifies the signature after
    decoding the payload, rather than trusting the payload and ignoring the
    signature.

    Args:
        token:     A valid JWT string to tamper with.
        claim:     The claim key to replace (e.g. 'sub', 'role', 'userId').
        new_value: The new value to assign to the claim. Must be JSON-serializable.

    Returns:
        JWT string with the modified payload and the original (now-invalid)
        signature: '{original_header}.{new_payload}.{original_signature}'

    Raises:
        ValueError: If the token is not in JWT format or the payload is not
                    valid JSON.
    """
    _require_jwt_format(token)
    segments = token.split(_JWT_SEPARATOR)

    payload = json.loads(_b64url_decode(segments[_JWT_PAYLOAD_INDEX]))
    payload[claim] = new_value
    new_payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")))

    return _JWT_SEPARATOR.join(
        [
            segments[_JWT_HEADER_INDEX],
            new_payload_b64,
            segments[_JWT_SIGNATURE_INDEX],
        ]
    )


def forge_expired(token: str, seconds_ago: int = 3600) -> str:
    """
    Return a JWT with the 'exp' claim set to a past Unix timestamp.

    The signature is no longer valid because the payload has changed. A secure
    server must reject this token with 401 because:
        1. The exp claim is in the past.
        2. The signature does not match the modified payload.

    Test 1.3 uses this function to verify that the server enforces token
    expiry independently of signature validation.

    Args:
        token:       A valid JWT string to modify.
        seconds_ago: How many seconds in the past to set the exp claim.
                     Defaults to 3600 (one hour ago). Must be positive.

    Returns:
        JWT string with exp set to (now - seconds_ago), keeping the original
        header and the original (now-invalid) signature.

    Raises:
        ValueError: If the token is not in JWT format, seconds_ago is not
                    positive, or the payload is not valid JSON.
    """
    if seconds_ago <= 0:
        raise ValueError(f"seconds_ago must be a positive integer. Got: {seconds_ago}")

    expired_timestamp = int(time.time()) - seconds_ago
    return forge_tampered_payload(token, _CLAIM_EXP, expired_timestamp)


def forge_strip_signature(token: str) -> str:
    """
    Return a JWT with the signature segment removed (empty string after last dot).

    Distinct from forge_alg_none: the header still declares the original
    algorithm. This tests whether the server rejects a token that has a valid
    header and payload structure but no signature, even when the declared
    algorithm is not 'none'.

    Some vulnerable implementations fall back to accepting unsigned tokens if
    the signature field is empty, regardless of the declared algorithm.

    Args:
        token: A valid JWT string.

    Returns:
        JWT string with empty signature: '{header}.{payload}.'

    Raises:
        ValueError: If the token is not in JWT format.
    """
    _require_jwt_format(token)
    segments = token.split(_JWT_SEPARATOR)
    return f"{segments[_JWT_HEADER_INDEX]}{_JWT_SEPARATOR}{segments[_JWT_PAYLOAD_INDEX]}{_JWT_SEPARATOR}"  # noqa: E501


def forge_hs256_key_confusion(public_key_pem: str, payload: dict[str, Any]) -> str:
    """
    Return a JWT signed with HS256 using an RSA public key as the HMAC secret.

    This attack (key confusion / algorithm substitution) exploits servers that
    accept both RS256 and HS256 without restricting the algorithm in the header.
    If the server validates the token using the public key as an HMAC secret
    (because the header says HS256), the attacker-controlled token passes
    verification.

    A secure server must either:
        a) Reject any token whose header declares an algorithm different from
           the one configured for the issuer, or
        b) Select the validation key based on the configured algorithm, not the
           header's alg claim.

    The 'cryptography' library is imported locally because this function is
    only called when a JWKS endpoint is available. Keeping the import local
    avoids a hard dependency at module load time and keeps the failure mode
    explicit: an ImportError here means the test should SKIP, not ERROR.

    Args:
        public_key_pem: PEM-encoded RSA public key string, typically fetched
                        from /.well-known/jwks.json and converted to PEM.
                        Used as the raw HMAC secret (not for RSA verification).
        payload:        JWT payload claims dict. Must include at minimum 'sub'
                        and 'exp'. Values must be JSON-serializable.

    Returns:
        Compact JWT string signed with HMAC-SHA256 using the public key bytes
        as the secret: '{header}.{payload}.{hmac_signature}'

    Raises:
        ImportError: If the 'cryptography' package is not installed.
        ValueError:  If public_key_pem is empty or payload is not serializable.
    """
    try:
        import hashlib as _hashlib
        import hmac as _hmac
    except ImportError as exc:
        raise ImportError(
            "Standard library modules 'hmac' and 'hashlib' are unavailable. "
            "This should never happen in a standard CPython installation."
        ) from exc

    if not public_key_pem or not public_key_pem.strip():
        raise ValueError("public_key_pem must not be empty.")

    header = {_CLAIM_ALG: _ALG_HS256, _CLAIM_TYP: _TYP_JWT}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")))

    signing_input = f"{header_b64}{_JWT_SEPARATOR}{payload_b64}"

    # Use the raw bytes of the PEM-encoded public key as the HMAC secret.
    # This replicates the exact byte sequence that a vulnerable RS256 server
    # would use when switching to HMAC validation with its known public key.
    secret_bytes = public_key_pem.encode("utf-8")
    mac = _hmac.new(secret_bytes, signing_input.encode("utf-8"), _hashlib.sha256)
    signature_b64 = _b64url_encode_bytes(mac.digest())

    return f"{signing_input}{_JWT_SEPARATOR}{signature_b64}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_jwt_format(token: str) -> None:
    """
    Raise ValueError if the token is not in three-segment JWT format.

    Args:
        token: The token string to validate.

    Raises:
        ValueError: If is_jwt_format(token) returns False.
    """
    if not is_jwt_format(token):
        raise ValueError(
            f"Token is not in JWT format (expected 3 dot-separated segments). "
            f"Got {len(token.split(_JWT_SEPARATOR))} segments. "
            f"Token preview: '{token[:40]}...'"
        )


def _b64url_decode(segment: str) -> bytes:
    """
    Decode a Base64url-encoded string to bytes, adding padding as needed.

    Base64url strips trailing '=' padding. Python's base64.b64decode requires
    padding to be present. This function restores it before decoding.

    Args:
        segment: A Base64url-encoded string (no padding).

    Returns:
        Decoded bytes.

    Raises:
        ValueError: If the segment cannot be decoded (malformed Base64url).
    """
    # Restore padding: Base64 segments must have length divisible by 4.
    padding_needed = (4 - len(segment) % 4) % 4
    padded = segment + "=" * padding_needed

    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise ValueError(
            f"Cannot Base64url-decode segment: {exc}. Segment preview: '{segment[:40]}'"
        ) from exc


def _b64url_encode(data: str) -> str:
    """
    Encode a string to Base64url without padding.

    Args:
        data: UTF-8 string to encode.

    Returns:
        Base64url-encoded string with no trailing '=' characters.
    """
    return _b64url_encode_bytes(data.encode("utf-8"))


def _b64url_encode_bytes(data: bytes) -> str:
    """
    Encode bytes to Base64url without padding.

    Args:
        data: Bytes to encode.

    Returns:
        Base64url-encoded string with no trailing '=' characters.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
