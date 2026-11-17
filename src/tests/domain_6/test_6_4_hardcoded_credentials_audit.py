"""
src/tests/domain_6/test_6_4_hardcoded_credentials_audit.py

Test 6.4: guarantee "service credentials are not hard-coded or exposed" (OWASP
API8:2023, CWE-798).

    debug_endpoint_no_secret  a debug or configuration path reached without a
                             credential (configured, or the tool's own:
                             src/core/sensitive_paths.py, kind CONFIGURATION,
                             under the root and each service prefix) returns no
                             credential: no credential pattern, and no
                             credential-named key (`DB_PASSWORD=...`, a JSON
                             or actuator `name`/`value` pair) with a real value;
    gateway_config_no_secret  the gateway's configuration values hold no
                             credential, by pattern or by a credential-named key
                             (white box, `Need.GATEWAY` optional).

Every credential found is registered as a secret before it is recorded, so the
outputs show it redacted. The oracle: info.oracle, generated on the test page.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import json
import re

import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import CONCEPT_NOT_ACCESSIBLE, category_of
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.gateway.base import CONCEPT_CONFIG_VALUES
from src.core.gateway.concepts import ConceptStatus, ConfigValue
from src.core.models import (
    Confidence,
    Finding,
    Outcome,
    Reference,
    ResponseCategory,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.sensitive_paths import SENSITIVE_PATHS, SensitiveKind
from src.core.test_metadata import Effect, Need, OracleCase, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.path_resolver import resolve_path_with_seed

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB_DEBUG: str = "debug_endpoint_no_secret"

# The derivation rule whose facts are the service prefixes (src/discovery), the
# base paths the default debug paths are asked under, besides the root.
_RULE_SERVICE_PREFIXES: str = "service_prefixes"
_SUB_CONFIG: str = "gateway_config_no_secret"

# A config value shorter than this is a placeholder, not a real credential.
_MIN_CREDENTIAL_VALUE_LENGTH: int = 8

# Strings that are placeholders, never a real credential (lowercased compare).
_PLACEHOLDER_STRINGS: frozenset[str] = frozenset(
    {
        "change_me",
        "changeme",
        "changeit",
        "change-me",
        "xxx",
        "yyy",
        "zzz",
        "placeholder",
        "example",
        "your_secret",
        "your-secret",
        "your_password",
        "your-password",
        "password",
        "password123",
        "secret",
        "secret123",
        "none",
        "null",
        "false",
        "true",
        "0",
        "1",
        "",
        "test",
        "testing",
        "sample",
        "replace_me",
        "replace-me",
        "todo",
    }
)
# A masked value ("******", Spring's actuator mask) is no credential.
_MASK_CHARACTERS: frozenset[str] = frozenset("*x•")

# Config-key fragments that suggest the value is a credential (substring, lower).
_SEMANTIC_CREDENTIAL_KEY_FRAGMENTS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "api-key",
        "auth_token",
        "authtoken",
        "access_token",
        "refresh_token",
        "bearer_token",
        "credential",
        "credentials",
        "private_key",
        "privatekey",
        "private-key",
        "access_key",
        "accesskey",
        "secret_key",
        "secretkey",
        "client_secret",
        "clientsecret",
        "db_password",
        "db_passwd",
        "database_password",
        "redis_password",
        "smtp_password",
        "authorization",
    }
)
# A key ending in "token" names one (`X-Auth-Token`, `GITHUB_TOKEN`); a
# fragment would also catch `token_type` or `max_tokens`.
_TOKEN_SUFFIX: str = "token"  # noqa: S105 -- a key suffix, not a credential
# The authentication schemes written before a credential in a header value.
_SCHEME_PREFIX: re.Pattern[str] = re.compile(r"^(?:bearer|basic|token)\s+", re.IGNORECASE)
# A list item that is a header ("X-Api-Key:value"): Kong writes the headers of
# request-transformer as a list, APISIX as a map.
_HEADER_ITEM: re.Pattern[str] = re.compile(r"^([A-Za-z0-9-]+)\s*:\s*(.+)$")
_LIST_ITEM_KEY: re.Pattern[str] = re.compile(r"\[\d+\]$")
# A `KEY=VALUE` (or `KEY: VALUE`) line of a served `.env` or properties file.
_ASSIGNMENT_LINE: re.Pattern[str] = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*[\"']?([^\"'\r\n]*)[\"']?\s*$",
    re.MULTILINE,
)

# Credential patterns, applied to both debug bodies and config values.
_CREDENTIAL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"://[^:@\s\"'/]{0,64}:[^@\s\"']{8,}@"), "URL-embedded credentials"),
    (re.compile(r"AKIA[A-Z0-9]{16}"), "AWS Access Key ID"),
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"), "Stripe live API key"),
    (re.compile(r"sk_test_[A-Za-z0-9]{24,}"), "Stripe test API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{60,}"), "GitHub fine-grained token"),
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
        "PEM private key material",
    ),
    (re.compile(r"xox[abpr]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Google API key"),
)

_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-13.3.1"),
    Reference(standard=Standard.NIST_SP, id="800-53r5", section="3.7"),
)
# A secret served by a debug path may come from the environment, not the code:
# CWE-215 (sensitive information in debugging code) and ASVS v5.0.0 13.4.2
# (debug modes disabled), 13.4.5 (monitoring endpoints not exposed), read
# 2026-11-16; until then it cited CWE-798.
_REFS_DEBUG: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.CWE, id="CWE-215"),
    Reference(standard=Standard.ASVS, id="v5.0.0-13.4.2"),
    Reference(standard=Standard.ASVS, id="v5.0.0-13.4.5"),
)

_ORACLE: tuple[OracleCase, ...] = (
    OracleCase(
        sub_test=_SUB_DEBUG,
        when="a path answers `2xx` without a credential and its body holds a credential "
        "pattern, or a credential-named key with a real value",
        outcome=Outcome.VIOLATION,
        detail="DEBUG_SECRET",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_DEBUG,
        when="it answers `2xx` and its body holds no credential",
        outcome=Outcome.ENFORCED,
        detail="DEBUG_NO_SECRET",
    ),
    OracleCase(
        sub_test=_SUB_DEBUG,
        when="it answers `404` or `410`",
        outcome=Outcome.ENFORCED,
        detail="DEBUG_NOT_FOUND",
    ),
    OracleCase(
        sub_test=_SUB_DEBUG,
        when="it is refused (`401`, `403`, `400`, `405`, ...)",
        outcome=Outcome.ENFORCED,
        detail="DEBUG_BLOCKED",
    ),
    OracleCase(
        sub_test=_SUB_DEBUG,
        when="it answers a redirect (not followed) or a status of no class",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="NOT_INTERPRETED",
    ),
    OracleCase(
        sub_test=_SUB_CONFIG,
        when="a gateway configuration value matches a credential pattern",
        outcome=Outcome.VIOLATION,
        detail="CONFIG_SECRET",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_CONFIG,
        when="a credential-named key (a header's name in a header list) holds a non-placeholder "
        "value of 8 characters or more, not a secret reference",
        outcome=Outcome.VIOLATION,
        detail="CONFIG_SECRET",
        confidence=Confidence.TENTATIVE,
    ),
    OracleCase(
        sub_test=_SUB_CONFIG,
        when="no value read holds a credential (secret references excepted)",
        outcome=Outcome.ENFORCED,
        detail="CONFIG_NO_SECRET",
    ),
    OracleCase(
        sub_test=_SUB_CONFIG,
        when="the read succeeded and returned no value at all",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="NO_CONFIG_VALUE",
    ),
    OracleCase(
        sub_test=_SUB_CONFIG,
        when="no gateway is configured",
        outcome=Outcome.NOT_APPLICABLE,
        detail="NO_GATEWAY",
    ),
    OracleCase(
        sub_test=_SUB_CONFIG,
        when="the gateway's adapter does not read configuration values",
        outcome=Outcome.NOT_APPLICABLE,
        detail="CONFIG_NOT_SUPPORTED",
    ),
)


class Test64Params(BaseModel):
    """Parameters of test 6.4."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    debug_endpoint_paths: tuple[str, ...] = Field(
        default=(),
        description=(
            "Paths of debug or actuator endpoints to probe unauthenticated for exposed "
            "credentials (e.g. /actuator/env, /debug/vars). Empty: the tool's paths that expose "
            "configuration (actuator/env, actuator/configprops, server-info, .env, .git/config, "
            ".git/HEAD), under the root and each service prefix."
        ),
    )


class Test64HardcodedCredentialsAudit(BaseTest[Test64Params]):
    """Test 6.4 -- whether a credential is exposed via a debug endpoint or the config."""

    info = TestInfo(
        id="6.4",
        name="Hardcoded Credentials Audit",
        priority=2,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-798",
        references=_REFERENCES,
        tags=("hardcoded-credentials", "secret-management"),
        optional_needs=(Need.GATEWAY,),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_DEBUG, _SUB_CONFIG),
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
        Probe the debug endpoints and scan the gateway configuration for secrets.

        Args:
            target:  The run's target (surface, gateway, path seed).
            context: The run's context (each credential found is registered as a secret).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish() or self._error(exc).
        """
        try:
            self._probe_debug_endpoints(target, context, client, store)
            self._audit_gateway_config(target, store)
            return self._finish()
        except SecurityClientError as exc:
            return self._error(exc)
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_6_4_unexpected_error", error=str(exc))
            return self._error(exc)

    def _probe_debug_endpoints(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> None:
        """Probe each debug path (configured, else _default_debug_paths) unauthenticated."""
        paths = self.params(target).debug_endpoint_paths or _default_debug_paths(target)
        for raw in paths:
            path = resolve_path_with_seed(raw, target.path_seed)
            try:
                response, record = client.request("GET", path, test_id=self.info.id)
            except SecurityClientError as exc:
                if exc.record is None:
                    raise
                self._judge(
                    record := exc.record, store, _SUB_DEBUG, Outcome.NOT_VERIFIABLE, "NO_RESPONSE"
                )
                continue
            category = category_of(record)
            uninformative = self._uninformative(record, _SUB_DEBUG)
            if uninformative is not None:
                # An unavailable, rate-limited or failing endpoint was not blocked:
                # it did not answer the question (rule 1).
                self._judge(record, store, _SUB_DEBUG, Outcome.NOT_VERIFIABLE, uninformative)
                continue
            if category == ResponseCategory.NOT_FOUND:
                self._judge(record, store, _SUB_DEBUG, Outcome.ENFORCED, "DEBUG_NOT_FOUND")
                continue
            if category in (ResponseCategory.REDIRECT, ResponseCategory.OTHER):
                # A redirect is not followed and may lead to the content
                # (until 2026-11-16 it counted as blocked).
                self._judge(record, store, _SUB_DEBUG, Outcome.NOT_VERIFIABLE, "NOT_INTERPRETED")
                continue
            if category != ResponseCategory.SERVED:
                self._judge(record, store, _SUB_DEBUG, Outcome.ENFORCED, "DEBUG_BLOCKED")
                continue
            found = _credentials_in_body(response.text)
            if found:
                # Registered before the record is kept: every output then shows
                # it redacted (until 2026-11-16 it was written in clear).
                for name, value in found:
                    context.register_secret(value, f"credential exposed at {path} ({name})")
                names = ", ".join(dict.fromkeys(name for name, _ in found))
                self._judge(
                    record,
                    store,
                    _SUB_DEBUG,
                    Outcome.VIOLATION,
                    "DEBUG_SECRET",
                    Finding(
                        title=f"Debug endpoint exposes a credential: {path}",
                        detail=(
                            f"GET {path} answered 2xx without a credential and its body holds a "
                            f"credential ({names}). A reachable debug or configuration path "
                            "returning secrets is a direct leak (OWASP API8:2023, CWE-215). Make "
                            "it return 401/403 or remove it, and rotate the credential."
                        ),
                        confidence=Confidence.FIRM,
                        references=list(_REFS_DEBUG),
                    ),
                )
                continue
            self._judge(record, store, _SUB_DEBUG, Outcome.ENFORCED, "DEBUG_NO_SECRET")

    def _audit_gateway_config(self, target: TargetContext, store: EvidenceStore) -> None:
        """Scan the gateway's configuration values for a credential."""
        gateway = target.gateway
        if gateway is None:
            self._record(_SUB_CONFIG, Outcome.NOT_APPLICABLE, "NO_GATEWAY")
            return
        answer = gateway.config_values()
        evidence_ref = self._record_gateway_concept(target, store, CONCEPT_CONFIG_VALUES, answer)
        if answer.status == ConceptStatus.NOT_SUPPORTED:
            self._record(_SUB_CONFIG, Outcome.NOT_APPLICABLE, "CONFIG_NOT_SUPPORTED")
            return
        if answer.status != ConceptStatus.READ:
            # The shared rule (until 2026-11-16 CONFIG_NOT_READABLE, for both).
            self._record(_SUB_CONFIG, Outcome.NOT_VERIFIABLE, CONCEPT_NOT_ACCESSIBLE)
            return
        if not answer.items:
            # The read succeeded and returned nothing: a gateway with no service
            # and no plugin, or a reader that found no value where there are some
            # (the shape of the Kong defect fixed on 2026-10-28). Either way the
            # scan examined nothing, so it cannot say a credential is absent.
            self._record(_SUB_CONFIG, Outcome.NOT_VERIFIABLE, "NO_CONFIG_VALUE")
            return
        references = tuple(prefix.lower() for prefix in gateway.secret_reference_prefixes)
        # The values found, by the object holding them and the value: a gateway
        # can give one value under two keys of the same object (Kong's
        # rate-limiting answers `config.redis.password` and the older
        # `config.redis_password`, measured 2026-11-15), one credential.
        flagged: dict[tuple[str, str], list[tuple[ConfigValue, Finding]]] = {}
        for item in answer.items:
            value = item.value.get_secret_value()
            if references and value.strip().lower().startswith(references):
                # A reference to a secret kept in a store or the environment is
                # what the remediation asks for, not a plaintext secret: the
                # adapter says how its gateway writes one.
                continue
            finding = _scan_config_value(item, evidence_ref)
            if finding is not None:
                flagged.setdefault((item.location, value), []).append((item, finding))
        for group in flagged.values():
            self._record(_SUB_CONFIG, Outcome.VIOLATION, "CONFIG_SECRET", _one_finding(group))
        if not flagged:
            self._record(_SUB_CONFIG, Outcome.ENFORCED, "CONFIG_NO_SECRET")


def _default_debug_paths(target: TargetContext) -> list[str]:
    """
    The tool's configuration-exposing paths under the root and each service prefix.

    Args:
        target: The run's target (the derived service prefixes).

    Returns:
        The paths, without duplicates, in a stable order.
    """
    bases = ["/"]
    surface = target.attack_surface
    if surface is not None:
        bases += [
            fact.value.rstrip("/") + "/" for fact in surface.derived_facts(_RULE_SERVICE_PREFIXES)
        ]
    suffixes = [p.suffix for p in SENSITIVE_PATHS if p.kind == SensitiveKind.CONFIGURATION]
    return list(dict.fromkeys(base + suffix for base in bases for suffix in suffixes))


def _scan_text(text: str) -> list[tuple[str, str]]:
    """Every credential pattern match in the text, as (pattern name, matched text)."""
    return [
        (name, match.group(0))
        for compiled, name in _CREDENTIAL_PATTERNS
        for match in compiled.finditer(text)
    ]


def _credentials_in_body(text: str) -> list[tuple[str, str]]:
    """
    The credentials a served body holds, as (what, value).

    A credential pattern anywhere, and each credential-named key with a real
    value: `KEY=VALUE` lines (`.env`, properties) and the pairs of a JSON body
    (an actuator's `name`/`value` and `{"value": ...}` included).
    """
    found = _scan_text(text)
    for key, value in [*_assignments(text), *_json_pairs(text)]:
        if _credential_named(key) and _real_value(value):
            found.append((f"credential-named key {key}", value.strip()))
    return found


def _assignments(text: str) -> list[tuple[str, str]]:
    """The `KEY=VALUE` lines of a body."""
    return [(m.group(1), m.group(2)) for m in _ASSIGNMENT_LINE.finditer(text)]


def _json_pairs(text: str) -> list[tuple[str, str]]:
    """The string pairs of a JSON body, at any depth."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    pairs: list[tuple[str, str]] = []
    stack: list[tuple[str, object]] = [("", data)]
    while stack:
        key, node = stack.pop()
        if isinstance(node, str):
            pairs.append((key, node))
        elif isinstance(node, dict):
            name, value = node.get("name"), node.get("value")
            if isinstance(name, str) and isinstance(value, str):
                pairs.append((name, value))
            elif isinstance(value, str) and key:
                pairs.append((key, value))
            stack.extend((str(k), v) for k, v in node.items())
        elif isinstance(node, list):
            stack.extend((key, item) for item in node)
    return pairs


def _credential_named(key: str) -> bool:
    """Whether a key names a credential (the last segment of a dotted one)."""
    last = key.rsplit(".", 1)[-1].lower()
    plain = last.replace("-", "_")
    return any(
        fragment in plain for fragment in _SEMANTIC_CREDENTIAL_KEY_FRAGMENTS
    ) or plain.endswith(_TOKEN_SUFFIX)


def _real_value(value: str) -> bool:
    """A value long enough, not a placeholder, not masked, without its scheme."""
    stripped = _SCHEME_PREFIX.sub("", value.strip())
    return (
        len(stripped) >= _MIN_CREDENTIAL_VALUE_LENGTH
        and stripped.lower() not in _PLACEHOLDER_STRINGS
        and not set(stripped.lower()) <= _MASK_CHARACTERS
    )


def _one_finding(group: list[tuple[ConfigValue, Finding]]) -> Finding:
    """
    One finding for one value found under one or more keys of the same object.

    The strongest finding of the group is kept (a matched pattern, FIRM, before
    a credential-named key, TENTATIVE), naming the other keys.

    Args:
        group: The values and their findings, in the order read.

    Returns:
        The finding to record.
    """
    item, finding = next(((i, f) for i, f in group if f.confidence == Confidence.FIRM), group[0])
    others = [other.key for other, _ in group if other is not item]
    if not others:
        return finding
    also = ", ".join(others)
    return finding.model_copy(
        update={
            "detail": (
                f"{finding.detail} The same value is also under {also} of {item.location}: one "
                "credential, reported once."
            )
        }
    )


def _scan_config_value(item: ConfigValue, evidence_ref: str) -> Finding | None:
    """A finding when a config value matches a pattern or a credential-named key, else None."""
    value = item.value.get_secret_value()
    key = item.key.rsplit(".", 1)[-1]
    header = _HEADER_ITEM.match(value.strip()) if _LIST_ITEM_KEY.search(key) else None
    if header is not None:
        # A header in a list: its name is the key (until 2026-11-16 the key
        # was `headers[3]`, never credential-named).
        key, value = header.group(1), header.group(2)
    matched = _scan_text(value)
    if matched:
        names = ", ".join(name for name, _ in matched)
        return Finding(
            title=f"Credential pattern in gateway config: {item.location}",
            detail=(
                f"Config key '{key}' ({item.key}) in {item.location} holds a value matching a "
                f"credential pattern ({names}). A plaintext secret in the gateway configuration "
                "cannot be rotated without a redeploy and leaks if the config is read (OWASP "
                "API8:2023, CWE-798, ASVS v5.0.0-13.3.1). Use a secret manager reference."
            ),
            confidence=Confidence.FIRM,
            evidence_ref=evidence_ref,
        )
    stripped = _SCHEME_PREFIX.sub("", value.strip())
    if _credential_named(key) and _real_value(value):
        return Finding(
            title=f"Probable plaintext credential in gateway config: {item.location}",
            detail=(
                f"Config key '{key}' ({item.key}) in {item.location} has a credential-like name "
                f"and a non-placeholder value of {len(stripped)} characters. If it is a real "
                "credential it must be a secret-manager reference, not a plaintext value (OWASP "
                "API8:2023, ASVS v5.0.0-13.3.1). Reported at lower confidence: the value is masked "
                "and judged by its key and length."
            ),
            confidence=Confidence.TENTATIVE,
            evidence_ref=evidence_ref,
        )
    return None
