"""
src/discovery/download.py

Download of the OpenAPI specification over HTTP/HTTPS, with the connection
settings of config.yaml `specification` (docs/architecture/design-decisions.md,
D3): its TLS context (system store plus certifi, ca_bundle, mutual TLS) and
its timeout. Used by Phase 2 (src/discovery/openapi.py) and by the
generate-seed command (src/discovery/seed_generator.py), which wrap the error
in their own.

Redirects are followed (a specification URL often redirects); a TLS failure, or
a TLS problem the server reports with an HTTP answer (nginx's pages), is
described with the key to set (src/core/tls.py) and never retried.

Dependency rule: imports from the stdlib, httpx, structlog and src.core.
"""

from __future__ import annotations

import ssl

import httpx
import structlog

from src.core.tls import (
    SPECIFICATION_TLS,
    build_ssl_context,
    certificate_answer,
    certificate_failure,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)


class SpecDownloadError(Exception):
    """The specification could not be downloaded; reason is a plain-words message."""

    def __init__(self, reason: str) -> None:
        """
        Initialize the error.

        Args:
            reason: What went wrong, with the key to set when there is one.
        """
        super().__init__(reason)
        self.reason: str = reason


def download_specification(
    url: str,
    timeout_seconds: float,
    tls_context: ssl.SSLContext | None = None,
) -> str:
    """
    Download the specification text.

    Args:
        url:             HTTP/HTTPS URL of the specification.
        timeout_seconds: Timeout of the download (connection and read).
        tls_context:     The context of specification.tls; None for the default
                         trust (system store plus certifi).

    Returns:
        The response body text.

    Raises:
        SpecDownloadError: TLS failure, timeout, connection error or non-2xx status.
    """
    context = tls_context if tls_context is not None else build_ssl_context(None, SPECIFICATION_TLS)
    log.debug("specification_download_started", url=url, timeout_seconds=timeout_seconds)
    try:
        with httpx.Client(verify=context, timeout=timeout_seconds, follow_redirects=True) as http:
            response = http.get(url)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        tls_reason = certificate_answer(
            exc.response.status_code, exc.response.text, SPECIFICATION_TLS
        )
        if tls_reason is not None:
            raise SpecDownloadError(tls_reason) from exc
        raise SpecDownloadError(
            f"HTTP {exc.response.status_code} when downloading the specification: check the URL."
        ) from exc
    except httpx.TimeoutException as exc:
        raise SpecDownloadError(
            f"the download timed out after {timeout_seconds}s ({exc}): raise "
            "specification.timeout if the server is slow."
        ) from exc
    except httpx.RequestError as exc:
        tls_reason = certificate_failure(exc, SPECIFICATION_TLS)
        raise SpecDownloadError(tls_reason or f"connection error: {exc}") from exc
    log.debug("specification_download_completed", url=url, size=len(response.text))
    return response.text
