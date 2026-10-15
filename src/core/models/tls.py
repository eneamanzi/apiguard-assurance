"""
src/core/models/tls.py

TlsSettings: the certificate settings of one connection of the tool.

Every connection (target, specification, gateway.admin, gateway.health) has
an optional `tls` block of this shape (docs/architecture/design-decisions.md,
D2):

    verify       check the server's certificate (default true)
    ca_bundle    trust only the authorities in this PEM file
    client_cert  the tool's certificate, for mutual TLS (PEM)
    client_key   its private key (PEM), always with client_cert

Absent, or with no ca_bundle, the connection trusts the operating system's
store plus certifi's list (src/core/tls.py builds the context).

Checks here, at load time (exit 10): the files exist and are files;
client_cert and client_key together; verify false with ca_bundle is a
contradiction. Paths are resolved to absolute ones (external tools run in
their own process). The PEM content, a certificate and a key that do not
match, and an encrypted key are checked when the context is built
(src/core/tls.py), still before any test.

The private key: only its path is configuration; its content is read only by
the TLS library, never logged.

Dependency rule: imports only from pydantic and the stdlib.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator


class TlsSettings(BaseModel):
    """Certificate settings of one connection."""

    model_config = {"frozen": True, "extra": "forbid"}

    verify: bool = Field(
        default=True,
        description=(
            "Check the server's certificate. false accepts any certificate (an impostor "
            "too): only for a quick test. Not with ca_bundle."
        ),
    )
    ca_bundle: Path | None = Field(
        default=None,
        description=(
            "PEM file of the certificate authorities to trust for this connection, "
            "instead of the system's store and certifi's list (as curl --cacert)."
        ),
    )
    client_cert: Path | None = Field(
        default=None,
        description="The tool's certificate (PEM), for a server that asks for mutual TLS.",
    )
    client_key: Path | None = Field(
        default=None,
        description=(
            "The private key of client_cert (PEM, not encrypted), always with it. Only the "
            "path is configuration: the content is never logged."
        ),
    )

    @field_validator("ca_bundle", "client_cert", "client_key", mode="after")
    @classmethod
    def existing_file(cls, value: Path | None) -> Path | None:
        """Require an existing file; store its absolute path."""
        if value is None:
            return None
        resolved = value.expanduser().resolve()
        if not resolved.is_file():
            raise ValueError(f"file not found: {resolved}")
        return resolved

    @model_validator(mode="after")
    def consistent(self) -> TlsSettings:
        """Require client_cert with client_key, and no ca_bundle without verification."""
        if (self.client_cert is None) != (self.client_key is None):
            raise ValueError("client_cert and client_key go together: set both or neither.")
        if not self.verify and self.ca_bundle is not None:
            raise ValueError(
                "verify: false with ca_bundle is a contradiction: remove one "
                "(ca_bundle checks the certificate against that authority)."
            )
        return self

    @property
    def has_client_certificate(self) -> bool:
        """True when the tool presents a certificate (mutual TLS)."""
        return self.client_cert is not None
