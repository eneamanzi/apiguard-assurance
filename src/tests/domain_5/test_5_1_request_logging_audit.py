"""
src/tests/domain_5/test_5_1_request_logging_audit.py

Test 5.1: guarantee "every request is logged with its metadata"
. NIST SP 800-92, OWASP ASVS v5.0.0-16.3.3 and 16.4.3,
NIST SP 800-53 Rev.5 AU-4(1), AU-9(2).

The methodology states the limit plainly: "without access to the logs this
guarantee cannot be checked empirically from outside." So the test audits the
one thing it can see from outside, the gateway's configuration: is a
plugin enabled that ships the request logs to a separate system (ASVS
v5.0.0-16.4.3)? Which plugins do that is the gateway adapter's knowledge (the
log-shipping concept): this test names no gateway (owner decision
2026-11-04). What it cannot see is the gateway's own access log: it is not in
the Admin API, so the test never claims that requests are not logged, only that
no plugin ships them. The log-content checks (the required fields,
the real source IP, log-injection resistance) need read access to the logs,
which the tool does not have on any target, so they are permanently out of
reach: stated as a note, never faked as a pass. One content check is readable
from the configuration: whether the record a shipper builds carries the
credential in clear (ASVS v5.0.0-16.2.5), since the gateway decides that
record (added 2026-11-17, owner).

    request_logging_configured  a plugin the adapter reports as shipping the
                               request logs is enabled on the gateway ->
                               ENFORCED/LOGS_SHIPPED; none ->
                               VIOLATION/LOGS_NOT_SHIPPED (FIRM: a collector
                               on the gateway's host is invisible here).
    secrets_not_shipped        per enabled shipper: the record carries a part
                               of the request where the target's credential
                               travels (the configured placement, the
                               specification's security schemes), not removed
                               -> VIOLATION/CREDENTIAL_SHIPPED (FIRM: a plugin
                               rewriting the request, or operator code, is not
                               read); none -> ENFORCED/CREDENTIAL_NOT_SHIPPED.

WHITE_BOX (the gateway Admin API), READ_ONLY.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base.
"""

from __future__ import annotations

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.gateway.base import CONCEPT_CONFIG_VALUES, CONCEPT_LOG_SHIPPING
from src.core.gateway.concepts import (
    REQUEST_PART_COOKIE,
    REQUEST_PART_EVERY,
    REQUEST_PART_HEADER,
    REQUEST_PART_QUERY,
    ConceptStatus,
    LogShipper,
    ShippedRequest,
    request_part,
)
from src.core.models import (
    Confidence,
    CredentialLocation,
    Finding,
    InfoNote,
    Outcome,
    Reference,
    SecuritySchemeType,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, Need, OracleCase, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB: str = "request_logging_configured"
_SUB_SECRETS: str = "secrets_not_shipped"

# Where a credential travels, as a part of the request (ShippedRequest): the
# header Authorization for the http, oauth2 and openIdConnect schemes (RFC
# 9110 11.6.2, RFC 6750), the named header, query parameter or cookie for an
# apiKey one. A cookie also travels in the Cookie header.
_AUTHORIZATION: str = "authorization"
_COOKIE_HEADER: str = "cookie"
_AUTHORIZATION_SCHEMES: frozenset[SecuritySchemeType] = frozenset(
    {SecuritySchemeType.HTTP, SecuritySchemeType.OAUTH2, SecuritySchemeType.OPENID_CONNECT}
)
_LOCATION_KINDS: dict[str, str] = {
    CredentialLocation.HEADER.value: REQUEST_PART_HEADER,
    CredentialLocation.QUERY.value: REQUEST_PART_QUERY,
    CredentialLocation.COOKIE.value: REQUEST_PART_COOKIE,
}


# What the tool cannot check from outside, permanently.
_CONTENT_CHECKS_NOTE: InfoNote = InfoNote(
    title="Log-content checks need log access (not done)",
    detail=(
        "This test audits that a plugin shipping the request logs is enabled on the gateway, "
        "and whether the record the gateway builds carries the credential. The methodology's "
        "other log-content checks (the required fields, the real source IP, log-injection "
        "resistance, secrets in bodies or in the application's own logs) need read access to "
        "the logs, which the tool does not have from outside: check them by hand on the log "
        "stream."
    ),
)
# Each read on its source 2026-11-17: ASVS v5.0.0-16.2.5 (credentials may not
# be logged, session tokens only hashed or masked), CWE-532 (sensitive
# information inserted into a log file).
_REFS_SECRETS: tuple[Reference, ...] = (
    Reference(standard=Standard.ASVS, id="v5.0.0-16.2.5"),
    Reference(standard=Standard.CWE, id="CWE-532"),
)

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS v5.0.0 source 2026-10-28: 16.3.3 (the security events of
    # the documentation are logged, bypass attempts included) and 16.4.3 (the
    # logs reach a logically separate system for analysis and alerting), which
    # is what a gateway logging plugin does. 16.2.1 (each log entry carries
    # the metadata needed to investigate: time, source, who, what, outcome).
    Reference(standard=Standard.ASVS, id="v5.0.0-16.4.3"),
    Reference(standard=Standard.NIST_SP, id="800-92"),
    Reference(standard=Standard.NIST_SP, id="800-53r5", section="3.3"),
)
# Until 2026-11-16 ASVS 16.3.3 (the application logs its security events) was
# cited too: a shipping plugin does not show it. The NIST controls are AU-4(1)
# and AU-9(2) (logs transferred to and kept on another system), in the AU family.

_ORACLE: tuple[OracleCase, ...] = (
    OracleCase(
        sub_test=_SUB,
        when="an enabled plugin ships the request logs of every client to another system",
        outcome=Outcome.ENFORCED,
        detail="LOGS_SHIPPED",
    ),
    OracleCase(
        sub_test=_SUB,
        when="no such plugin enabled (one bound to a single consumer does not count), among "
        "configuration values that were read",
        outcome=Outcome.VIOLATION,
        detail="LOGS_NOT_SHIPPED",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB,
        when="no shipper, and the configuration read returned no value at all",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="NO_CONFIG_VALUE",
    ),
    OracleCase(
        sub_test=_SUB_SECRETS,
        when="an enabled shipper's record carries a part of the request where the credential "
        "travels (the configured placement, a security scheme of the specification), and "
        "nothing removes it for all the traffic it logs (FIRM: a plugin rewriting the "
        "request, or operator code, is not read)",
        outcome=Outcome.VIOLATION,
        detail="CREDENTIAL_SHIPPED",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_SECRETS,
        when="the record carries it, and a setting removes it for part of that traffic only, "
        "or with a pattern that may leave part of it",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="CREDENTIAL_REMOVED_IN_PART",
    ),
    OracleCase(
        sub_test=_SUB_SECRETS,
        when="the record carries none of those parts, or they are removed for all its traffic",
        outcome=Outcome.ENFORCED,
        detail="CREDENTIAL_NOT_SHIPPED",
    ),
    OracleCase(
        sub_test=_SUB_SECRETS,
        when="the gateway does not state what the record carries (operator code builds it)",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="RECORD_NOT_STATED",
    ),
    OracleCase(
        sub_test=_SUB_SECRETS,
        when="neither the configuration nor the specification says where a credential travels",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="CREDENTIAL_PLACE_UNKNOWN",
    ),
    OracleCase(
        sub_test=_SUB_SECRETS,
        when="no enabled shipper",
        outcome=Outcome.NOT_APPLICABLE,
        detail="NO_SHIPPER",
    ),
)


class Test51RequestLoggingAudit(BaseTest):
    """
    Test 5.1 -- whether the gateway is configured to log requests.

    The oracle is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="5.1",
        name="Request Logging Audit",
        priority=1,
        strategy=TestStrategy.WHITE_BOX,
        cwe="CWE-778",
        references=_REFERENCES,
        tags=("logging", "auditing"),
        needs=(Need.GATEWAY,),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB, _SUB_SECRETS),
        oracle=_ORACLE,
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Read the gateway configuration and judge whether a logging plugin is on.

        Args:
            target:  The run's target (gateway adapter).
            context: Unused.
            client:  Unused (the audit reads the gateway, sends no request).
            store:   The test's evidence store.

        Returns:
            self._finish(), self._skip(...), or self._error(exc).
        """
        del context, client
        try:
            gateway = target.gateway
            assert gateway is not None  # noqa: S101 -- Need.GATEWAY, checked by the engine
            # The shippers first: the configuration values are only the guard
            # against an empty read when none is found (until 2026-11-16 they
            # were read first, and an adapter without them could not judge).
            shipping = gateway.log_shipping()
            evidence_ref = self._record_gateway_concept(
                target, store, CONCEPT_LOG_SHIPPING, shipping
            )
            if shipping.status != ConceptStatus.READ:
                return self._unread_concept(CONCEPT_LOG_SHIPPING, shipping, evidence_ref)
            # A disabled plugin ships nothing.
            enabled = [s for s in shipping.items if s.enabled]
            plugins = sorted({f"{s.plugin} ({s.source})" for s in enabled})
            if plugins:
                self._record(_SUB, Outcome.ENFORCED, "LOGS_SHIPPED")
                self._audit_secrets(target, enabled, evidence_ref)
                return self._finish(
                    notes=[
                        InfoNote(
                            title="Log-shipping plugin configured",
                            detail=(
                                f"The gateway ships its request logs with: {', '.join(plugins)}."
                            ),
                        ),
                        _CONTENT_CHECKS_NOTE,
                    ]
                )
            self._record(_SUB_SECRETS, Outcome.NOT_APPLICABLE, "NO_SHIPPER")
            answer = gateway.config_values()
            config_ref = self._record_gateway_concept(target, store, CONCEPT_CONFIG_VALUES, answer)
            if answer.status == ConceptStatus.READ and not answer.items:
                # The read succeeded and returned nothing: a gateway with no
                # service and no plugin, or a reader that found no value where
                # there are some. "No logging plugin" would then accuse the
                # target of a gap this run never looked for.
                self._record(_SUB, Outcome.NOT_VERIFIABLE, "NO_CONFIG_VALUE")
                return self._finish(
                    notes=[
                        InfoNote(
                            title="The gateway configuration read was empty",
                            detail=(
                                "The gateway answered its configuration endpoints with no value "
                                "at all, so this run cannot say whether requests are logged. "
                                f"Evidence: {config_ref}."
                            ),
                        )
                    ]
                )
            self._record(
                _SUB,
                Outcome.VIOLATION,
                "LOGS_NOT_SHIPPED",
                Finding(
                    title="No gateway plugin ships the request logs to a separate system",
                    detail=(
                        "The gateway's configuration has no plugin enabled that sends request "
                        "logs to another system (as the gateway adapter recognises them). The "
                        "gateway may still write "
                        "its own access log, which the Admin API does not show; kept on the "
                        "gateway's host, it is lost or altered with that host, while ASVS "
                        "v5.0.0-16.4.3 asks that logs reach a logically separate system for "
                        "analysis and alerting (also NIST SP 800-92, NIST SP 800-53 Rev.5 "
                        "AU-4(1)). "
                        "Enable a plugin that ships structured logs to the log store, or confirm "
                        "that a collector on the gateway's host already ships its access log."
                    ),
                    confidence=Confidence.FIRM,
                    evidence_ref=evidence_ref,
                ),
            )
            return self._finish(notes=[_CONTENT_CHECKS_NOTE])
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_5_1_unexpected_error", error=str(exc))
            return self._error(exc)

    def _audit_secrets(
        self, target: TargetContext, shippers: list[LogShipper], evidence_ref: str
    ) -> None:
        """
        Judge, per enabled shipper, whether its record carries the credential.

        Args:
            target:       The run's target (credential placement, specification).
            shippers:     The enabled log shippers.
            evidence_ref: The log-shipping concept artifact.
        """
        places = _credential_places(target)
        if not places:
            self._record(_SUB_SECRETS, Outcome.NOT_VERIFIABLE, "CREDENTIAL_PLACE_UNKNOWN")
            return
        for shipper in shippers:
            record = shipper.request
            if record is None:
                self._record(_SUB_SECRETS, Outcome.NOT_VERIFIABLE, "RECORD_NOT_STATED")
                continue
            shipped = [label for label, keys in places if _shipped(record, keys, sure=True)]
            if not shipped and any(_shipped(record, keys, sure=False) for _, keys in places):
                self._record(_SUB_SECRETS, Outcome.NOT_VERIFIABLE, "CREDENTIAL_REMOVED_IN_PART")
            elif shipped:
                self._record(
                    _SUB_SECRETS,
                    Outcome.VIOLATION,
                    "CREDENTIAL_SHIPPED",
                    Finding(
                        title=f"Credential shipped in the request logs by '{shipper.plugin}'",
                        detail=(
                            f"The log plugin {shipper.plugin} ({shipper.source}) sends to "
                            f"another system a record carrying {', '.join(shipped)}, where the "
                            "target's credential travels, and the gateway's configuration "
                            "removes it nowhere: anyone reading the log store can replay the "
                            "credentials it holds. ASVS v5.0.0-16.2.5: credentials are not "
                            "logged, session tokens only hashed or masked. Remove or mask that "
                            "part before the record is built (a log format without it, the "
                            "gateway's masking or hide-credentials option). A plugin rewriting "
                            "the request, or operator code, is not read here."
                        ),
                        confidence=Confidence.FIRM,
                        evidence_ref=evidence_ref,
                        references=list(_REFS_SECRETS),
                    ),
                )
            else:
                self._record(_SUB_SECRETS, Outcome.ENFORCED, "CREDENTIAL_NOT_SHIPPED")


def _credential_places(target: TargetContext) -> list[tuple[str, tuple[str, ...]]]:
    """
    Where the target's credential travels: a label and the request parts carrying it.

    From the configured placement and the specification's security schemes;
    a cookie is carried by its own name and by the Cookie header.
    """
    found: list[tuple[str, str]] = []
    placement = target.credential_placement
    if placement is not None:
        found.append((placement.location.value, placement.name))
    surface = target.attack_surface
    for scheme in surface.security_schemes if surface is not None else []:
        if scheme.scheme_type in _AUTHORIZATION_SCHEMES:
            found.append((CredentialLocation.HEADER.value, _AUTHORIZATION))
        elif scheme.scheme_type == SecuritySchemeType.API_KEY and scheme.parameter_name:
            found.append((str(scheme.location), scheme.parameter_name))
    places: dict[str, tuple[str, ...]] = {}
    for location, name in found:
        kind = _LOCATION_KINDS.get(location)
        if kind is None:
            continue
        keys = [request_part(kind, name)]
        if kind == REQUEST_PART_COOKIE:
            keys.append(request_part(REQUEST_PART_HEADER, _COOKIE_HEADER))
        places[f"the {kind} '{name.lower()}'"] = tuple(keys)
    return sorted(places.items())


def _shipped(record: ShippedRequest, keys: tuple[str, ...], sure: bool) -> bool:
    """
    Whether the record carries one of these parts, not removed.

    Args:
        record: What a shipper's record carries.
        keys:   The request parts one credential travels in.
        sure:   True: only a part nothing removes even in part; False: also one
                removed for part of the traffic.
    """
    cookie = keys[0] if keys[0].startswith(f"{REQUEST_PART_COOKIE}:") else None
    for key in keys:
        every = request_part(key.split(":", 1)[0], REQUEST_PART_EVERY)
        if not (key in record.carries or every in record.carries):
            continue
        # In the Cookie header, the cookie itself may be taken out (jwt-auth).
        names = {key} | ({cookie} if cookie and key != cookie else set())
        if names & set(record.removed):
            continue
        if not sure or not names & set(record.removed_in_part):
            return True
    return False
