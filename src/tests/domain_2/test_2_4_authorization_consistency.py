"""
src/tests/domain_2/test_2_4_authorization_consistency.py

Test 2.4: guarantee "authorization is consistent across equivalent endpoints"
. OWASP API8:2023.

An older or alternative version of an operation must enforce the same
authorization as the documented one. The classic failure is a versioning drift:
`GET /api/v2/users/{id}` requires a credential, the new or old
`GET /api/v3/users/{id}` forgets the check (crAPI challenge 3 reaches an older
version of the password-reset flow).

The equivalent endpoints are the version siblings derived in Phase 2
(`version_siblings`): the undocumented API versions next to the documented ones.
For each documented operation that requires authentication, the test sends the
**same request without a credential** to both the documented path and its
sibling, and compares: the documented one must refuse; if the sibling serves it,
the sibling dropped the check. The violation is proven by contrast (the
documented operation refuses the very same unauthenticated request), so it does
not rest on the heuristic alone.

Only safe methods are sent, without a credential: the test changes nothing and
needs no account (BLACK_BOX). It does not ask whether the sibling exists as a
shadow path (that is 0.1); it asks whether, where it exists, it enforces the
same policy (rule 10).

Sub-test: `version_sibling_consistent`.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import re

import structlog

from src.core.assessment_test import category_of
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.models import (
    Confidence,
    EvidenceRecord,
    Finding,
    Outcome,
    Reference,
    ResponseCategory,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.path_resolver import resolve_path_with_seed

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The Phase-2 rule whose facts name the version siblings, and the shape of a
# version segment (src/discovery/derivation.py). Written here, not imported: a
# test never imports discovery/ (the dependency rule); both must match the rule.
_RULE_VERSION_SIBLINGS: str = "version_siblings"
VERSION_SEGMENT: re.Pattern[str] = re.compile(r"^v\d+(\.\d+)*$", re.IGNORECASE)

# The single sub-test.
_SUB: str = "version_sibling_consistent"

# The methods sent without a credential: the safe ones (the test changes nothing).
_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})

# The refusal categories: the request without a credential was turned away.
_REFUSED: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.UNAUTHENTICATED, ResponseCategory.FORBIDDEN}
)

# Categories that say nothing about the guarantee (rule 1).
_SPOILING: dict[ResponseCategory, str] = {
    ResponseCategory.UPSTREAM_UNAVAILABLE: "UPSTREAM_UNAVAILABLE",
    ResponseCategory.RATE_LIMITED: "RATE_LIMITED",
    ResponseCategory.NO_RESPONSE: "NO_RESPONSE",
    ResponseCategory.SERVER_ERROR: "SERVER_ERROR",
}

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS v5.0.0 source 2026-10-22: 8.1.1 (one access-control policy,
    # enforced the same everywhere).
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-8.1.1"),
    Reference(standard=Standard.NIST_SP, id="800-53", section="3"),
)


class Test24AuthorizationConsistency(BaseTest):
    """
    Test 2.4 -- whether a version sibling enforces the same authorization.

    The oracle is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="2.4",
        name="Authorization Consistency",
        priority=1,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-285",
        references=_REFERENCES,
        tags=("authorization", "consistency"),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB,),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Compare each protected operation with its version siblings, no credential.

        Args:
            target:  The run's target (surface, derived knowledge, path seed).
            context: The run's context (unused: no credential).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._requires_attack_surface(...), or
            self._error(exc).
        """
        del context
        try:
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            groups = self._sibling_pairs(target)
            if not groups:
                self._record(_SUB, Outcome.NOT_APPLICABLE, "NO_VERSION_SIBLING")
                return self._finish(message="No protected operation has a version sibling.")
            for candidate, pairs in groups.items():
                self._compare_version(client, store, target, candidate, pairs)
            return self._finish()
        except SecurityClientError as exc:
            return self._error(exc)

    def _sibling_pairs(self, target: TargetContext) -> dict[str, list[tuple[str, str, str]]]:
        """
        The comparison pairs, grouped by version candidate so a whole absent
        version is skipped with one probe.

        For each version-sibling candidate (`/identity/api/v3`) and each
        documented protected safe-method operation under the same base but a
        different version, build the sibling path by swapping the version.

        Args:
            target: The run's target (surface, derived facts).

        Returns:
            candidate prefix (`/identity/api/v3`) -> list of
            (method, documented path, sibling path), unique.
        """
        surface = target.attack_surface
        if surface is None:
            return {}
        protected = [
            e for e in surface.endpoints if e.method.upper() in _SAFE_METHODS and e.requires_auth
        ]
        groups: dict[str, list[tuple[str, str, str]]] = {}
        seen: set[tuple[str, str, str]] = set()
        for fact in surface.derived_facts(_RULE_VERSION_SIBLINGS):
            base, _, cand_version = fact.value.rpartition("/")
            if not VERSION_SEGMENT.match(cand_version):
                continue
            for endpoint in protected:
                sibling = _swap_version(endpoint.path, base, cand_version)
                if sibling is None:
                    continue
                key = (endpoint.method.upper(), endpoint.path, sibling)
                if key in seen:
                    continue
                seen.add(key)
                groups.setdefault(fact.value, []).append(key)
        return groups

    def _compare_version(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        target: TargetContext,
        candidate: str,
        pairs: list[tuple[str, str, str]],
    ) -> None:
        """
        Compare every pair of one version candidate, after checking the version
        exists at all.

        A representative sibling is probed first: if the candidate version is
        entirely absent (a 404 of its own shape), the whole group is one
        NOT_APPLICABLE/VERSION_ABSENT instead of a probe per endpoint (a large
        API with a single documented version would otherwise send hundreds of
        requests for nothing).

        Args:
            client:    The run's HTTP client.
            store:     The test's evidence store.
            target:    The run's target (path seed).
            candidate: The candidate version prefix, e.g. `/identity/api/v3`.
            pairs:     The (method, documented, sibling) triples of this version.
        """
        method, _documented, sibling = pairs[0]
        probe_path = resolve_path_with_seed(sibling, target.path_seed)
        representative = _send(client, method, probe_path, self.info.id)
        if representative is not None and category_of(representative) == ResponseCategory.NOT_FOUND:
            self._step(representative)
            self._record(_SUB, Outcome.NOT_APPLICABLE, "VERSION_ABSENT")
            return
        for method, documented, sibling in pairs:
            self._compare(client, store, method, documented, sibling, target)

    def _compare(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        method: str,
        documented: str,
        sibling: str,
        target: TargetContext,
    ) -> None:
        """
        Send the unauthenticated request to the documented path and its sibling.

        Args:
            client:     The run's HTTP client.
            store:      The test's evidence store.
            method:     The safe method.
            documented: The documented (template) path.
            sibling:    The sibling (template) path.
            target:     The run's target (path seed).
        """
        doc_record = _send(
            client, method, resolve_path_with_seed(documented, target.path_seed), self.info.id
        )
        if doc_record is None or category_of(doc_record) not in _REFUSED:
            # The documented operation was not refused without a credential (it is
            # public, or the probe could not decide): there is no protected policy
            # to be inconsistent with. That is 1.1's question, not this one.
            self._record(_SUB, Outcome.NOT_APPLICABLE, "DOCUMENTED_NOT_PROTECTED")
            if doc_record is not None:
                self._step(doc_record)
            return
        self._step(doc_record)
        sib_path = resolve_path_with_seed(sibling, target.path_seed)
        sib_record = _send(client, method, sib_path, self.info.id)
        if sib_record is None:
            self._record(_SUB, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return
        category = category_of(sib_record)
        if category in _SPOILING:
            self._judge(sib_record, store, _SUB, Outcome.NOT_VERIFIABLE, _SPOILING[category])
            return
        if category == ResponseCategory.SERVED:
            self._judge(
                sib_record,
                store,
                _SUB,
                Outcome.VIOLATION,
                "VERSION_DROPS_AUTH",
                Finding(
                    title=f"Version sibling drops the authorization check: {method} {sib_path}",
                    detail=(
                        f"The documented operation {method} {documented} refuses an "
                        f"unauthenticated request (HTTP {doc_record.response_status_code}), but "
                        f"its version sibling {method} {sib_path} served it "
                        f"(HTTP {sib_record.response_status_code}). An older or alternative "
                        "version enforces a different policy, so the control is bypassed by "
                        "changing the version (OWASP API8:2023). Apply the same authorization to "
                        "every version, or retire the undocumented one."
                    ),
                    confidence=Confidence.CERTAIN,
                ),
            )
            return
        if category == ResponseCategory.NOT_FOUND:
            self._judge(sib_record, store, _SUB, Outcome.NOT_APPLICABLE, "SIBLING_ABSENT")
            return
        if category in _REFUSED:
            self._judge(sib_record, store, _SUB, Outcome.ENFORCED, "SIBLING_REFUSED")
            return
        self._judge(sib_record, store, _SUB, Outcome.NOT_VERIFIABLE, category.name)


def _swap_version(path: str, base: str, cand_version: str) -> str | None:
    """
    The sibling of a path under `base`, with its version segment set to cand_version.

    Args:
        path:         A documented path, e.g. /identity/api/v2/user/dashboard.
        base:         The base of the version candidate, e.g. /identity/api.
        cand_version: The candidate version segment, e.g. v3.

    Returns:
        The sibling path (/identity/api/v3/user/dashboard), or None when `path`
        is not under `base` with a version segment right after it, or when its
        version already equals the candidate.
    """
    if not path.startswith(base + "/"):
        return None
    remainder = path[len(base) + 1 :]
    head, _, tail = remainder.partition("/")
    if not VERSION_SEGMENT.match(head) or head == cand_version:
        return None
    return f"{base}/{cand_version}/{tail}" if tail else f"{base}/{cand_version}"


def _send(client: SecurityClient, method: str, path: str, test_id: str) -> EvidenceRecord | None:
    """One unauthenticated request, its record or None on a transport failure."""
    try:
        _response, record = client.request(method, path, test_id=test_id)
    except SecurityClientError as exc:
        return exc.record
    return record
