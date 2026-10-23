"""
src/tests/domain_6/test_6_4_hardcoded_credentials_audit.py

Test 6.4: guarantee "service credentials are not hard-coded or exposed"
(rewritten, docs/project/test-review/group-i.md). OWASP API8:2023, CWE-798.

Two sub-tests on one guarantee (credentials not exposed):

    debug_endpoint_no_secret  a debug endpoint (`/actuator/env`, `/debug/vars`,
                             ...) reached without a credential does not return a
                             value matching a credential pattern (black box);
    gateway_config_no_secret  the gateway's configuration values hold no
                             credential, by pattern or by a credential-named key
                             with a non-placeholder value (white box, the Admin
                             API, `Need.GATEWAY` optional).

A debug endpoint's paths come from the configuration (none configured: the
sub-test is NOT_APPLICABLE). The config scan needs a gateway; without one it is
NOT_APPLICABLE. Secret values are masked in the evidence (`SecretStr`).

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import re

import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import category_of
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
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.path_resolver import resolve_path_with_seed

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB_DEBUG: str = "debug_endpoint_no_secret"
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
    }
)

# Credential patterns, applied to both debug bodies and config values.
_CREDENTIAL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"://[^:@\s\"']{1,64}:[^@\s\"']{8,}@"), "URL-embedded credentials"),
    (re.compile(r"AKIA[A-Z0-9]{16}"), "AWS Access Key ID"),
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"), "Stripe live API key"),
    (re.compile(r"sk_test_[A-Za-z0-9]{24,}"), "Stripe test API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "PEM private key material"),
)

_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-13.3.1"),
    Reference(standard=Standard.NIST_SP, id="800-53", section="5.4"),
)


class Test64Params(BaseModel):
    """Parameters of test 6.4."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    debug_endpoint_paths: tuple[str, ...] = Field(
        default=(),
        description=(
            "Paths of debug or actuator endpoints to probe unauthenticated for exposed "
            "credentials (e.g. /actuator/env, /debug/vars). Empty: the debug sub-test is not "
            "applicable."
        ),
    )


class Test64HardcodedCredentialsAudit(BaseTest[Test64Params]):
    """
    Test 6.4 -- whether a credential is exposed via a debug endpoint or the config.

    The oracle of each sub-test is in the module docstring and on the test page.
    """

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
            context: Unused.
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish() or self._error(exc).
        """
        del context
        try:
            self._probe_debug_endpoints(target, client, store)
            self._audit_gateway_config(target, store)
            return self._finish()
        except SecurityClientError as exc:
            return self._error(exc)
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_6_4_unexpected_error", error=str(exc))
            return self._error(exc)

    def _probe_debug_endpoints(
        self, target: TargetContext, client: SecurityClient, store: EvidenceStore
    ) -> None:
        """Probe each configured debug path unauthenticated for an exposed credential."""
        paths = self.params(target).debug_endpoint_paths
        if not paths:
            self._record(_SUB_DEBUG, Outcome.NOT_APPLICABLE, "NO_DEBUG_PATH")
            return
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
            if category_of(record) != ResponseCategory.SERVED:
                self._judge(record, store, _SUB_DEBUG, Outcome.ENFORCED, "DEBUG_BLOCKED")
                continue
            matched = _scan_text(response.text)
            if matched:
                names = ", ".join(name for name, _ in matched)
                self._judge(
                    record,
                    store,
                    _SUB_DEBUG,
                    Outcome.VIOLATION,
                    "DEBUG_SECRET",
                    Finding(
                        title=f"Debug endpoint exposes a credential: {path}",
                        detail=(
                            f"GET {path} answered 2xx without a credential and its body matches a "
                            f"credential pattern ({names}). A reachable debug endpoint returning "
                            "secrets is a direct leak (OWASP API8:2023, CWE-798). Make it return "
                            "401/403 or remove it, and keep secrets in a secret manager."
                        ),
                        confidence=Confidence.FIRM,
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
        if answer.status != ConceptStatus.READ:
            self._record(_SUB_CONFIG, Outcome.NOT_VERIFIABLE, "CONFIG_NOT_READABLE")
            return
        found = False
        for item in answer.items:
            finding = _scan_config_value(item, evidence_ref)
            if finding is not None:
                found = True
                self._record(_SUB_CONFIG, Outcome.VIOLATION, "CONFIG_SECRET", finding)
        if not found:
            self._record(_SUB_CONFIG, Outcome.ENFORCED, "CONFIG_NO_SECRET")


def _scan_text(text: str) -> list[tuple[str, str]]:
    """Credential patterns matching the text, as (name, redacted snippet)."""
    results: list[tuple[str, str]] = []
    for compiled, name in _CREDENTIAL_PATTERNS:
        match = compiled.search(text)
        if match:
            raw = match.group(0)
            snippet = raw[:4] + "[REDACTED]" + raw[-4:] if len(raw) > 12 else raw[:2] + "[REDACTED]"
            results.append((name, snippet))
    return results


def _scan_config_value(item: ConfigValue, evidence_ref: str) -> Finding | None:
    """A finding when a config value matches a pattern or a credential-named key, else None."""
    value = item.value.get_secret_value()
    key = item.key.rsplit(".", 1)[-1]
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
    key_lower = key.lower()
    semantic = any(fragment in key_lower for fragment in _SEMANTIC_CREDENTIAL_KEY_FRAGMENTS)
    stripped = value.strip()
    placeholder = stripped.lower() in _PLACEHOLDER_STRINGS
    if semantic and len(stripped) >= _MIN_CREDENTIAL_VALUE_LENGTH and not placeholder:
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
