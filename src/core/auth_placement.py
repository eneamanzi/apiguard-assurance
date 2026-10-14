"""
src/core/auth_placement.py

Where and how the tool sends a credential: the placement.

The method (credentials.auth_type) obtains a credential for each role; the
placement says where it goes in a request (a header, a query parameter or a
cookie), under which name and after which prefix. It is resolved once per
run, after the specification is loaded, from:

    the security schemes the specification declares (AttackSurface),
    credentials.security_scheme  which of them, when there are several,
    credentials.send_as          what the scheme leaves out (a prefix), or the
                                 whole placement when no scheme is declared.

Rules (docs/project/auth-survey.md, section 5):
    - basic always sends 'Authorization: Basic <base64>' (RFC 7617);
    - token methods use a scheme that can carry a token: apiKey, http bearer,
      oauth2, openIdConnect (the last three as 'Authorization: Bearer', RFC
      6750); http basic and mutualTLS cannot;
    - one usable scheme is taken as is; several need security_scheme; none
      needs send_as with 'in' and 'name';
    - send_as 'in' / 'name' must agree with the chosen scheme; a prefix is
      accepted only by an apiKey scheme (bearer has its own).
A configuration that does not satisfy them raises ConfigurationError: the
run stops before any test, and validate-config reports it.

Dependency rule: this module imports only from pydantic, the stdlib,
src.core.models and src.core.exceptions.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from src.core.exceptions import ConfigurationError
from src.core.models import (
    AuthType,
    CredentialLocation,
    RuntimeCredentials,
    SecuritySchemeRecord,
    SecuritySchemeType,
)

_AUTHORIZATION_HEADER: str = "Authorization"
_BASIC_PREFIX: str = "Basic "
_BEARER_PREFIX: str = "Bearer "
_HTTP_SCHEME_BEARER: str = "bearer"
_COOKIE_HEADER: str = "Cookie"

_CONFIG_PATH_SCHEME: str = "credentials.security_scheme"
_CONFIG_PATH_SEND_AS: str = "credentials.send_as"

# Scheme types that always carry the token as 'Authorization: Bearer'.
_BEARER_TYPES: frozenset[SecuritySchemeType] = frozenset(
    {SecuritySchemeType.OAUTH2, SecuritySchemeType.OPENID_CONNECT}
)


# ---------------------------------------------------------------------------
# CredentialPlacement
# ---------------------------------------------------------------------------


class RequestAuthParts(BaseModel):
    """The parts of a request that carry a credential."""

    model_config = {"frozen": True}

    headers: dict[str, str] = Field(default_factory=dict, description="Headers to send.")
    params: dict[str, str] = Field(default_factory=dict, description="Query parameters to send.")


class CredentialPlacement(BaseModel):
    """Where and how a credential is sent in every authenticated request."""

    model_config = {"frozen": True}

    location: CredentialLocation = Field(description="Header, query parameter or cookie.")
    name: str = Field(min_length=1, description="Name of the header, parameter or cookie.")
    prefix: str = Field(default="", description="Text written before the credential.")
    source: str = Field(
        min_length=1,
        description="What decided it, e.g. \"scheme 'bearerAuth'\" or 'send_as', for logs.",
    )

    def request_parts(self, credential: str) -> RequestAuthParts:
        """
        Return the request parts carrying a credential.

        Args:
            credential: The credential as the method produced it (a token, or
                        the base64 'user:password' of HTTP Basic).

        Returns:
            Headers and query parameters to merge into the request.
        """
        value = f"{self.prefix}{credential}"
        if self.location is CredentialLocation.HEADER:
            return RequestAuthParts(headers={self.name: value})
        if self.location is CredentialLocation.QUERY:
            return RequestAuthParts(params={self.name: value})
        return RequestAuthParts(headers={_COOKIE_HEADER: f"{self.name}={value}"})


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def resolve_placement(
    credentials: RuntimeCredentials,
    schemes: list[SecuritySchemeRecord],
) -> CredentialPlacement | None:
    """
    Resolve where and how credentials are sent, from the configuration and the spec.

    Args:
        credentials: The credentials section of config.yaml.
        schemes:     The security schemes the specification declares.

    Returns:
        The placement, or None when no method is configured (no credentials).

    Raises:
        ConfigurationError: When the configuration and the specification do not
            determine one placement (see the module docstring).
    """
    if credentials.auth_type is None:
        return None
    if credentials.auth_type is AuthType.BASIC:
        return CredentialPlacement(
            location=CredentialLocation.HEADER,
            name=_AUTHORIZATION_HEADER,
            prefix=_BASIC_PREFIX,
            source="HTTP Basic (RFC 7617)",
        )

    scheme = _choose_scheme(credentials, schemes)
    if scheme is None:
        return _placement_from_send_as(credentials, schemes)
    return _placement_from_scheme(credentials, scheme)


def _can_carry_token(scheme: SecuritySchemeRecord) -> bool:
    """True for the schemes a token can be sent with."""
    if scheme.scheme_type is SecuritySchemeType.API_KEY:
        return True
    if scheme.scheme_type is SecuritySchemeType.HTTP:
        return scheme.http_scheme == _HTTP_SCHEME_BEARER
    return scheme.scheme_type in _BEARER_TYPES


def _names(schemes: list[SecuritySchemeRecord]) -> str:
    """Comma-separated scheme names, for messages."""
    return ", ".join(scheme.name for scheme in schemes) or "(none)"


def _choose_scheme(
    credentials: RuntimeCredentials,
    schemes: list[SecuritySchemeRecord],
) -> SecuritySchemeRecord | None:
    """The scheme to use: the one named, the only usable one, or None when none is usable."""
    method = credentials.auth_type.value if credentials.auth_type is not None else ""
    usable = [scheme for scheme in schemes if _can_carry_token(scheme)]
    if credentials.security_scheme is not None:
        named = next((s for s in schemes if s.name == credentials.security_scheme), None)
        if named is None:
            raise ConfigurationError(
                message=(
                    f"credentials.security_scheme '{credentials.security_scheme}' is not declared "
                    f"by the specification. Declared schemes: {_names(schemes)}."
                ),
                config_path=_CONFIG_PATH_SCHEME,
            )
        if not _can_carry_token(named):
            raise ConfigurationError(
                message=(
                    f"Scheme '{named.name}' ({named.scheme_type.value}"
                    f"{' ' + named.http_scheme if named.http_scheme else ''}) cannot carry the "
                    f"token of auth_type '{method}'. Schemes that can: {_names(usable)}."
                ),
                config_path=_CONFIG_PATH_SCHEME,
            )
        return named
    if len(usable) > 1:
        raise ConfigurationError(
            message=(
                f"Set credentials.security_scheme: the specification declares {len(usable)} "
                f"schemes that can carry a token: {_names(usable)}."
            ),
            config_path=_CONFIG_PATH_SCHEME,
        )
    return usable[0] if usable else None


def _placement_from_scheme(
    credentials: RuntimeCredentials,
    scheme: SecuritySchemeRecord,
) -> CredentialPlacement:
    """The placement of a declared scheme, completed by send_as."""
    send_as = credentials.send_as
    source = f"scheme '{scheme.name}'"
    if scheme.scheme_type is SecuritySchemeType.API_KEY:
        location = CredentialLocation(str(scheme.location))
        name = str(scheme.parameter_name)
        fixed_prefix: str | None = None
    else:
        location, name, fixed_prefix = (
            CredentialLocation.HEADER,
            _AUTHORIZATION_HEADER,
            _BEARER_PREFIX,
        )

    if send_as is not None:
        if send_as.location is not None and send_as.location is not location:
            raise ConfigurationError(
                message=(
                    f"credentials.send_as.in '{send_as.location.value}' contradicts {source}, "
                    f"which sends the credential in the {location.value}. Remove send_as.in."
                ),
                config_path=_CONFIG_PATH_SEND_AS,
            )
        if send_as.name is not None and not _same_name(send_as.name, name, location):
            raise ConfigurationError(
                message=(
                    f"credentials.send_as.name '{send_as.name}' contradicts {source}, whose "
                    f"name is '{name}'. Remove send_as.name."
                ),
                config_path=_CONFIG_PATH_SEND_AS,
            )
        if send_as.prefix is not None and fixed_prefix is not None:
            raise ConfigurationError(
                message=(
                    f"{source} sends 'Authorization: Bearer <token>': it takes no "
                    "credentials.send_as.prefix. Remove it."
                ),
                config_path=_CONFIG_PATH_SEND_AS,
            )
    if fixed_prefix is not None:
        prefix = fixed_prefix
    else:
        prefix = send_as.prefix if send_as is not None and send_as.prefix else ""
        if send_as is not None and send_as.prefix:
            source = f"{source} + send_as.prefix"
    return CredentialPlacement(location=location, name=name, prefix=prefix, source=source)


def _placement_from_send_as(
    credentials: RuntimeCredentials,
    schemes: list[SecuritySchemeRecord],
) -> CredentialPlacement:
    """The placement written in send_as, when the specification declares no usable scheme."""
    send_as = credentials.send_as
    if send_as is None or send_as.location is None or send_as.name is None:
        declared = f" (declared: {_names(schemes)}, none can carry a token)" if schemes else ""
        raise ConfigurationError(
            message=(
                f"The specification declares no scheme to send the token with{declared}: "
                "set credentials.send_as with 'in' (header, query or cookie) and 'name', "
                "and 'prefix' if needed."
            ),
            config_path=_CONFIG_PATH_SEND_AS,
        )
    return CredentialPlacement(
        location=send_as.location,
        name=send_as.name,
        prefix=send_as.prefix or "",
        source="send_as",
    )


def _same_name(given: str, declared: str, location: CredentialLocation) -> bool:
    """Compare names; header names are case-insensitive (RFC 9110)."""
    if location is CredentialLocation.HEADER:
        return given.lower() == declared.lower()
    return given == declared
