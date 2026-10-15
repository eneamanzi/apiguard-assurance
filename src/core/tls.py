"""
src/core/tls.py

The TLS context of each connection of the tool, built once at startup from
its TlsSettings (docs/architecture/design-decisions.md, D2).

Trust:
    no settings, or no ca_bundle   the operating system's store (truststore)
                                   plus certifi's list: a company authority
                                   installed by IT and proxies inspecting
                                   HTTPS work, and never fewer authorities
                                   than httpx's default;
    ca_bundle                      only the authorities in that file (as
                                   curl --cacert);
    verify: false                  no check of the server's certificate.
A client certificate (mutual TLS) is loaded in every case.

SSL_CERT_FILE / SSL_CERT_DIR do not change what the tool trusts: the
configuration says it. HTTPS_PROXY is handled by httpx as before.

Errors raise ConfigurationError, so that the run stops with exit 10 before any
test: a file that is not PEM, a certificate and a key that do not match, an
encrypted key (Python's TLS library would ask for its password on the
terminal and a CI job would hang: the tool never lets it ask).

Warnings (returned, the caller logs them): a private key readable by other
users of the machine (as SSH does), a tls block on an http:// URL (ignored).

certificate_failure() turns a TLS failure of a connection into a message
that names the problem and the key to set; a TLS failure is never retried.
certificate_answer() does the same for a TLS problem a server reports with an
HTTP answer instead of refusing the connection: nginx (and the gateways built
on it, such as APISIX) completes the handshake without a client certificate and
answers 400 with a fixed page (its codes 495, 496, 497, sent as 400:
https://nginx.org/en/docs/http/ngx_http_ssl_module.html#errors).

Dependency rule: imports from the stdlib, certifi, truststore,
src.core.models and src.core.exceptions.
"""

from __future__ import annotations

import ssl
import stat
from pathlib import Path

import certifi
import truststore

from src.core.exceptions import ConfigurationError
from src.core.models import TlsSettings

# Configuration paths of the four connections' tls blocks: named in messages.
TARGET_TLS: str = "target.tls"
SPECIFICATION_TLS: str = "specification.tls"
GATEWAY_ADMIN_TLS: str = "gateway.admin.tls"
GATEWAY_HEALTH_TLS: str = "gateway.health.tls"

_HTTP_SCHEME: str = "http://"
# Permission bits of group and others: a private key must have none of them.
_OTHERS_PERMISSIONS: int = stat.S_IRWXG | stat.S_IRWXO
# OpenSSL reasons of a server refusing the client certificate (TLS 1.3 and 1.2 alerts).
_CLIENT_CERTIFICATE_REFUSED: tuple[str, ...] = (
    "CERTIFICATE_REQUIRED",
    "BAD_CERTIFICATE",
    "UNKNOWN_CA",
    "CERTIFICATE_UNKNOWN",
    "HANDSHAKE_FAILURE",
)
# OpenSSL reasons of a peer that does not speak TLS on that port.
_NOT_TLS: tuple[str, ...] = ("WRONG_VERSION_NUMBER", "RECORD_LAYER_FAILURE")
# nginx's answers to a TLS problem: status 400 and the title of a fixed page
# (src/http/ngx_http_special_response.c, pages 495, 496 and 497).
_NGINX_TLS_STATUS: int = 400
_NGINX_CLIENT_CERTIFICATE_INVALID: str = "<title>400 The SSL certificate error</title>"
_NGINX_CLIENT_CERTIFICATE_MISSING: str = "<title>400 No required SSL certificate was sent</title>"
_NGINX_PLAIN_HTTP_TO_HTTPS: str = "<title>400 The plain HTTP request was sent to HTTPS port</title>"


class _NoPasswordError(Exception):
    """Raised by the password callback: the tool never asks for a key's password."""


def _refuse_password() -> str:
    """Password callback of load_cert_chain: an encrypted key is refused, never prompted for."""
    raise _NoPasswordError


def build_ssl_context(settings: TlsSettings | None, where: str) -> ssl.SSLContext:
    """
    Build the TLS context of one connection.

    Args:
        settings: The connection's tls block, or None for the defaults.
        where:    The configuration path of the block, for error messages
                  (e.g. 'gateway.admin.tls').

    Returns:
        The context to pass to the HTTP client.

    Raises:
        ConfigurationError: A file that is not valid PEM, a certificate and a
            key that do not match, or an encrypted key.
    """
    tls = settings if settings is not None else TlsSettings()
    if not tls.verify:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # nosec B501 -- the user asked for verify: false
    elif tls.ca_bundle is not None:
        try:
            context = ssl.create_default_context(cafile=str(tls.ca_bundle))
        except (ssl.SSLError, OSError) as exc:
            raise ConfigurationError(
                f"{where}.ca_bundle: {tls.ca_bundle} is not a PEM file of certificate "
                f"authorities ({exc}).",
                config_path=f"{where}.ca_bundle",
            ) from exc
    else:
        context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=certifi.where())

    if tls.client_cert is not None and tls.client_key is not None:
        try:
            context.load_cert_chain(
                certfile=str(tls.client_cert),
                keyfile=str(tls.client_key),
                password=_refuse_password,
            )
        except _NoPasswordError as exc:
            raise ConfigurationError(
                f"{where}.client_key: {tls.client_key} is encrypted; encrypted keys are not "
                "supported yet: decrypt it (e.g. openssl pkey -in key.pem -out plain.pem) "
                "and keep the result readable only by you.",
                config_path=f"{where}.client_key",
            ) from exc
        except (ssl.SSLError, OSError) as exc:
            raise ConfigurationError(
                f"{where}: cannot load client_cert {tls.client_cert} with client_key "
                f"{tls.client_key}: not PEM files, or the key does not belong to the "
                f"certificate ({exc}).",
                config_path=f"{where}.client_cert",
            ) from exc
    return context


def tls_warnings(settings: TlsSettings | None, url: str | None, where: str) -> list[str]:
    """
    Return the warnings about one connection's tls block.

    Args:
        settings: The connection's tls block, or None.
        url:      The connection's URL (None for a local file).
        where:    The configuration path of the block.

    Returns:
        Messages to log; empty when there is nothing to say.
    """
    if settings is None:
        return []
    warnings: list[str] = []
    if url is not None and url.lower().startswith(_HTTP_SCHEME):
        warnings.append(f"{where} is ignored: the URL {url} is plain http.")
    if settings.client_key is not None and _readable_by_others(settings.client_key):
        warnings.append(
            f"{where}.client_key {settings.client_key} can be read by other users of this "
            "machine: restrict it (chmod 600)."
        )
    return warnings


def certificate_failure(exc: BaseException, where: str) -> str | None:
    """
    Describe a TLS failure in plain words, with the configuration key to set.

    Looks through the exception's causes for the ssl error httpx wraps in a
    ConnectError. A TLS failure is not transient: the caller must not retry it.

    Args:
        exc:   An exception raised by the HTTP client.
        where: The configuration path of the connection's tls block
               (e.g. 'gateway.admin.tls').

    Returns:
        The message, or None when the failure is not about TLS.
    """
    error = _ssl_error_in(exc)
    if error is None:
        return None
    if isinstance(error, ssl.SSLCertVerificationError):
        detail = error.verify_message or str(error)
        lowered = detail.lower()
        if "hostname mismatch" in lowered or "ip address mismatch" in lowered:
            return (
                f"the server's certificate is not valid for the address used ({detail}): "
                "use in the URL a name the certificate was issued for."
            )
        if "expired" in lowered or "not yet valid" in lowered:
            return f"the server's certificate cannot be used now ({detail})."
        return (
            f"the server's certificate is not trusted ({detail}): set {where}.ca_bundle to "
            "the authority that issued it (or install that authority in the system's store)."
        )
    reason = (error.reason or str(error)).upper()
    if any(marker in reason for marker in _CLIENT_CERTIFICATE_REFUSED):
        return (
            f"the server refused the connection: it asks for a client certificate it accepts "
            f"({error.reason}); check {where}.client_cert and {where}.client_key."
        )
    if any(marker in reason for marker in _NOT_TLS):
        return (
            f"the server did not answer with TLS ({error.reason}): the address may be plain "
            "http, or the port wrong."
        )
    return f"the TLS handshake failed ({error.reason or error})."


def certificate_answer(status_code: int, body: str, where: str) -> str | None:
    """
    Describe a TLS problem a server reported with an HTTP answer (nginx's pages).

    Args:
        status_code: The status of the answer.
        body:        The body of the answer.
        where:       The configuration path of the connection's tls block
                     (e.g. 'gateway.admin.tls').

    Returns:
        The message, with the key to set, or None when the answer is not one of them.
    """
    if status_code != _NGINX_TLS_STATUS:
        return None
    if _NGINX_CLIENT_CERTIFICATE_MISSING in body:
        return (
            'the server requires a client certificate and none was sent (nginx: "No required '
            f'SSL certificate was sent"): set {where}.client_cert and {where}.client_key.'
        )
    if _NGINX_CLIENT_CERTIFICATE_INVALID in body:
        return (
            'the server did not accept the client certificate (nginx: "The SSL certificate '
            f'error"): check {where}.client_cert and {where}.client_key (issued by an '
            "authority the server trusts, not expired)."
        )
    if _NGINX_PLAIN_HTTP_TO_HTTPS in body:
        return (
            'a plain HTTP request reached an HTTPS port (nginx: "The plain HTTP request was '
            'sent to HTTPS port"): use https:// in the URL.'
        )
    return None


def _ssl_error_in(exc: BaseException) -> ssl.SSLError | None:
    """The first ssl.SSLError among an exception and its causes."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, ssl.SSLError):
            return current
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return None


def _readable_by_others(path: Path) -> bool:
    """True when group or others have any permission on the file."""
    return bool(path.stat().st_mode & _OTHERS_PERMISSIONS)
