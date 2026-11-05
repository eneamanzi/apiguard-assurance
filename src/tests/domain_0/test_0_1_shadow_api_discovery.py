"""
src/tests/domain_0/test_0_1_shadow_api_discovery.py

Test 0.1: guarantee "every exposed endpoint is documented", the part that needs
the specification. The path search is the
companion external test ext.0.1.ffuf.

Three sub-tests, each asking only "does something exist outside the
specification":

    undeclared_methods     a documented path accepts a method the specification
                           does not declare for it;
    undocumented_versions  a version of a documented path that the
                           specification does not document answers;
    gateway_route_drift    the gateway routes something no documented path
                           falls under (optional need GATEWAY: without it the
                           sub-test is NOT_APPLICABLE and the others run).

What a method means is never assumed: each answer is compared with what the
same method gives on random paths under the same parent (the calibration of
src/core/references.py). A path answering an undeclared method exactly as an
unknown path does does not serve it; a path answering differently treats that
method specially, which is the evidence the sub-test needs. Measured on the
labs (2026-10-21): Forgejo answers 405 to a method token it does not know and
404 to an undeclared POST on a path it serves with GET, so comparing those two
answers would report every such path; comparing like with like does not.
On a path with parameters the random siblings are the same route as the probe,
so the comparison says nothing: there only a 2xx (the method was executed) or a
405 (it was refused) is evidence, and any other answer is NOT_VERIFIABLE
(NONEXISTENT_OBJECT), since a handled method on an object that does not exist
and an ignored one can answer alike.

Where the target refuses an unauthenticated request before it looks at the
method (crAPI's identity service answers 401 to any path and any method, as
its calibration shows), the two answers are identical and say nothing: the
case is NOT_VERIFIABLE, not enforced (2026-10-22: 47 of 202 judgements on
crAPI were counted as enforced before this rule).

Safety of the method probes (owner, 2026-10-21: more discovery is better, with
cleanup):

    - a path with parameters is probed on random values of the declared type
      (random_sibling_path), never on the operator's resources, so a handled
      write finds no object to act on;
    - a path without parameters is probed with an empty JSON body;
    - anything a probe creates (2xx with a Location) is deleted at once; what
      cannot be deleted is stated in the result (rule 7).

Dependency rule: imports from stdlib, structlog, pydantic and src.core, plus
src.tests.base and src.tests.helpers. The name of the derivation rule is a
constant here: a test never imports src/discovery/.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import structlog

from src.core.assessment_test import category_of
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.gateway.base import CONCEPT_ROUTES
from src.core.gateway.concepts import ConceptStatus, RouteMatch, RoutePath
from src.core.models import (
    Confidence,
    EndpointRecord,
    EvidenceRecord,
    Finding,
    InfoNote,
    Outcome,
    Reference,
    ResponseCategory,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.references import Similarity, random_sibling_path, sibling_pattern
from src.core.response_category import categorize
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.sampling import sample_by_service

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The sub-tests, in the order the page lists them.
_SUB_METHODS: str = "undeclared_methods"
_SUB_VERSIONS: str = "undocumented_versions"
_SUB_ROUTES: str = "gateway_route_drift"

# The methods probed when the specification does not declare them for a path.
# HEAD is left out: RFC 9110 §9.3.2 makes it implied by GET.
PROBED_METHODS: tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE")

# TRACE makes a server send back the request it received (RFC 9110 section
# 9.3.8); enabled, it lets a script read headers it should not (Cross-Site
# Tracing). Usually a server-wide setting, so it is asked once per service
# (_trace), not per path, and judged on the echo: a comparison with random
# paths would read a server echoing everywhere as "like an unknown path".
_TRACE: str = "TRACE"
# What a TRACE echo starts with: the request line the server received.
_TRACE_ECHO: re.Pattern[str] = re.compile(r"^\s*TRACE\s+/", re.IGNORECASE)
# Answers that refuse TRACE outright.
_TRACE_REFUSALS: frozenset[int] = frozenset({405, 501})

# The methods that carry a body; an empty JSON object is sent with them.
_BODY_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})
# Values put in place of a template's parameters when a gateway route is a
# regular expression (_route_covers): a number and a word.
_REGEX_PARAMETER_SAMPLES: tuple[str, ...] = ("1", "a")
# The methods that change something when they are accepted (_clean_up).
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_EMPTY_BODY: dict[str, object] = {}

# The categories in which an answer is a refusal of the request itself: the
# target did not look at the method or the path, so an unauthenticated probe
# cannot tell whether either is served.
_REFUSING: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.UNAUTHENTICATED, ResponseCategory.FORBIDDEN}
)

# The answer categories that say nothing about the guarantee: the target was
# unavailable or protecting itself (rule 1).
_SPOILING: dict[ResponseCategory, str] = {
    ResponseCategory.UPSTREAM_UNAVAILABLE: "UPSTREAM_UNAVAILABLE",
    ResponseCategory.RATE_LIMITED: "RATE_LIMITED",
    ResponseCategory.NO_RESPONSE: "NO_RESPONSE",
    ResponseCategory.SERVER_ERROR: "SERVER_ERROR",
}

# The name of the derivation rule whose facts give the undocumented versions
# (src/discovery/derivation.py; a test does not import that package).
RULE_VERSION_SIBLINGS: str = "version_siblings"

# A path segment shaped as an API version, as the derivation rule reads it.
_VERSION_SEGMENT: re.Pattern[str] = re.compile(r"^v\d+(\.\d+)*$", re.IGNORECASE)
_TEMPLATE_PARAMETER: re.Pattern[str] = re.compile(r"\{([^}/]+)\}")

# The header a created object's address comes in (RFC 9110 §10.2.2).
_LOCATION_HEADER: str = "location"

# How many items a note lists by name.
_NOTE_EXAMPLES: int = 12

_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API9:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-4.1.4"),
    Reference(standard=Standard.WSTG, id="WSTG-v42-CONF-06"),
)


class Test01ShadowApiDiscovery(BaseTest):
    """
    Test 0.1 -- what the specification itself reveals about undocumented exposure.

    The oracle of each sub-test is in the module docstring and on the test
    page; the path search is ext.0.1.ffuf.
    """

    info = TestInfo(
        id="0.1",
        name="Undeclared Methods, Undocumented Versions and Gateway Route Drift",
        priority=0,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-912",
        references=_REFERENCES,
        tags=("inventory", "shadow-api"),
        optional_needs=(Need.GATEWAY,),
        effect=Effect.STRESSES_TARGET,
        sub_tests=(_SUB_METHODS, _SUB_VERSIONS, _SUB_ROUTES),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Run the three sub-tests and return the computed result.

        Args:
            target:  The run's target (surface, derived facts, path_seed, gateway).
            context: The run's context (reference responses).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), or self._skip() without an attack surface, or
            self._error(exc) on an unexpected exception.
        """
        try:
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            notes: list[InfoNote] = []
            notes += self._methods(target, context, client, store)
            notes += self._versions(target, context, client, store)
            notes += self._routes(target, store)
            return self._finish(notes=notes)
        except Exception as exc:  # noqa: BLE001 -- the test's top-level handler
            return self._error(exc)

    # ------------------------------------------------------------------
    # Sub-test: undeclared_methods
    # ------------------------------------------------------------------

    def _methods(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[InfoNote]:
        """
        Probe every method the specification does not declare, path by path,
        and TRACE once per service (_trace).

        Args:
            target:  The run's target.
            context: The run's context (the calibration).
            client:  The HTTP client.
            store:   The evidence store.

        Returns:
            The note of anything a probe created and could not delete.
        """
        surface = target.attack_surface
        declared: dict[str, set[str]] = {}
        endpoints: dict[str, EndpointRecord] = {}
        for endpoint in surface.endpoints if surface is not None else []:
            declared.setdefault(endpoint.path, set()).add(endpoint.method)
            endpoints.setdefault(endpoint.path, endpoint)
        left_behind: list[str] = []
        captured = _captured_by_a_template(declared)
        for template, methods in declared.items():
            endpoint = endpoints[template]
            path = self._concrete_path(template, endpoint)
            for method in (m for m in PROBED_METHODS if m not in methods):
                self._probe_method(
                    method,
                    path,
                    endpoint,
                    context,
                    client,
                    store,
                    left_behind,
                    sibling_captured=template in captured,
                )
        self._trace(target, client, store)
        if not left_behind:
            return []
        more = len(left_behind) - _NOTE_EXAMPLES
        return [
            InfoNote(
                title=f"{len(left_behind)} accepted write(s) not undone",
                detail=(
                    "An undeclared write method was accepted, and what it created or changed was "
                    f"not removed: {', '.join(left_behind[:_NOTE_EXAMPLES])}"
                    + (f" and {more} more" if more > 0 else "")
                    + ". Check them by hand. Only an object the probe surely created (a Location, "
                    "or a PUT on a random path) is deleted: a DELETE on a real path could remove "
                    "a real resource."
                ),
            )
        ]

    def _trace(self, target: TargetContext, client: SecurityClient, store: EvidenceStore) -> None:
        """
        Ask TRACE once per service and judge the echo (module docstring, _TRACE).

        A 405 or 501 refuses it; an answer that does not send the request back
        does not echo it; a 2xx that echoes the request line is the
        misconfiguration, CERTAIN; a 2xx without the echo is not interpreted.

        Args:
            target: The run's target (one documented GET per service).
            client: The HTTP client.
            store:  The evidence store.
        """
        for _method, path, template in sample_by_service(target, frozenset({"GET"})):
            try:
                _response, record = client.request(_TRACE, path, test_id=self.info.id)
            except SecurityClientError as exc:
                if exc.record is None:
                    raise
                self._judge(exc.record, store, _SUB_METHODS, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
                continue
            category = category_of(record)
            spoiled = _SPOILING.get(category)
            echoed = _TRACE_ECHO.match(record.response_body or "") is not None
            if spoiled is not None:
                self._judge(record, store, _SUB_METHODS, Outcome.NOT_VERIFIABLE, spoiled)
            elif record.response_status_code in _TRACE_REFUSALS:
                self._judge(record, store, _SUB_METHODS, Outcome.ENFORCED, "METHOD_REJECTED")
            elif category == ResponseCategory.SERVED and echoed:
                self._judge(
                    record,
                    store,
                    _SUB_METHODS,
                    Outcome.VIOLATION,
                    "TRACE_ECHOED",
                    finding=Finding(
                        title=f"TRACE enabled: {template}",
                        detail=(
                            f"TRACE {path} (no credential) answered "
                            f"{record.response_status_code} with the request sent back in the "
                            "body. A server that echoes TRACE lets a script in a browser read "
                            "the headers of its own request, cookies and credentials included "
                            "(Cross-Site Tracing), and it is a method the specification does "
                            "not declare. Disable TRACE at the gateway and the server (OWASP "
                            "ASVS v5.0.0-4.1.4)."
                        ),
                        confidence=Confidence.CERTAIN,
                    ),
                )
            elif category == ResponseCategory.SERVED:
                self._judge(
                    record, store, _SUB_METHODS, Outcome.NOT_VERIFIABLE, "TRACE_SERVED_NO_ECHO"
                )
            else:
                self._judge(record, store, _SUB_METHODS, Outcome.ENFORCED, "TRACE_NOT_SERVED")

    @staticmethod
    def _concrete_path(template: str, endpoint: EndpointRecord) -> str:
        """
        The path to probe: random values of the declared type in every parameter.

        The operator's resources (path_seed) are deliberately not used: the
        sub-tests ask whether an endpoint exists or knows a method, which a
        non-existent object answers just as well, and nothing real can be
        changed (rule 7).

        Args:
            template: The path as the specification writes it.
            endpoint: Its first operation (for the parameters' declared types).

        Returns:
            A concrete path, addressing objects that do not exist.
        """
        if not _TEMPLATE_PARAMETER.search(template):
            return template
        return random_sibling_path(template, endpoint.parameters)

    def _probe_method(  # noqa: PLR0913 -- one probe needs all of it
        self,
        method: str,
        path: str,
        endpoint: EndpointRecord,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        left_behind: list[str],
        *,
        sibling_captured: bool = False,
    ) -> None:
        """
        Send one undeclared method and judge the answer (module docstring).

        sibling_captured: a documented path with a parameter in place of this
        path's last segment exists (/users/{id} next to /users/search), so its
        random siblings reach that route, not an unknown path: a different
        answer from them is no evidence.

        Args:
            method:      The undeclared method.
            path:        The concrete path probed.
            endpoint:    The documented operation of that path (its template and
                         the declared types of its parameters).
            context:     The run's context (the calibration).
            client:      The HTTP client.
            store:       The evidence store.
            left_behind: Filled with what a handled write created and could not
                         be deleted.
        """
        body = _EMPTY_BODY if method in _BODY_METHODS else None
        try:
            _response, record = client.request(method, path, test_id=self.info.id, json=body)
        except SecurityClientError as exc:
            if exc.record is None:
                raise
            self._judge(exc.record, store, _SUB_METHODS, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return
        category = category_of(record)
        detail = _SPOILING.get(category)
        if detail is not None:
            self._judge(record, store, _SUB_METHODS, Outcome.NOT_VERIFIABLE, detail)
            return
        if category == ResponseCategory.METHOD_NOT_ALLOWED:
            # The standard refusal of a method a resource does not support
            # (RFC 9110 section 15.5.6): no calibration needed.
            self._judge(record, store, _SUB_METHODS, Outcome.ENFORCED, "METHOD_REJECTED")
            return
        references = context.references
        similarity = references.same_as_unknown(
            record, template_path=endpoint.path, parameters=endpoint.parameters
        )
        point = references.calibration(sibling_pattern(endpoint.path, endpoint.parameters), method)
        if similarity == Similarity.UNRELIABLE:
            self._judge(record, store, _SUB_METHODS, Outcome.NOT_VERIFIABLE, "CALIBRATION_UNSTABLE")
            return
        served = category == ResponseCategory.SERVED
        # On a path with parameters the random siblings are the same route as
        # the probe (sibling_pattern keeps the template): the comparison sets
        # the method against itself, and an answer short of 2xx or 405 cannot
        # tell a method the route ignores from one it handles on an object
        # that does not exist.
        parametric = _TEMPLATE_PARAMETER.search(endpoint.path) is not None
        if not served and (similarity == Similarity.SAME_AS_UNKNOWN or parametric):
            refused = (
                point.fingerprint is not None
                and categorize(point.fingerprint.status_code) in _REFUSING
            )
            if refused:
                outcome, detail = Outcome.NOT_VERIFIABLE, "REFUSED_BEFORE_ROUTING"
            elif parametric:
                outcome, detail = Outcome.NOT_VERIFIABLE, "NONEXISTENT_OBJECT"
            else:
                outcome, detail = Outcome.ENFORCED, "METHOD_NOT_SERVED"
            self._judge(record, store, _SUB_METHODS, outcome, detail)
            return
        if not served and sibling_captured:
            self._judge(
                record, store, _SUB_METHODS, Outcome.NOT_VERIFIABLE, "SIBLING_ROUTE_DOCUMENTED"
            )
            return
        if served and similarity == Similarity.SAME_AS_UNKNOWN and not parametric:
            # Random siblings are served the same 2xx (a catch-all answers every
            # path): this path does not treat the method specially.
            self._judge(record, store, _SUB_METHODS, Outcome.NOT_VERIFIABLE, "SERVED_LIKE_UNKNOWN")
            return
        if served:
            self._clean_up(record, path, client, store, left_behind, parametric=parametric)
        self._judge(
            record,
            store,
            _SUB_METHODS,
            Outcome.VIOLATION,
            "UNDECLARED_METHOD_HANDLED" if served else "UNDECLARED_METHOD_KNOWN",
            finding=Finding(
                title=(
                    f"Undeclared method handled: {method} {endpoint.path}"
                    if served
                    else f"Undeclared method known: {method} {endpoint.path}"
                ),
                detail=(
                    f"{method} {path} (no credential) answered {record.response_status_code} "
                    f"({category.value})"
                    + (
                        ": the method was executed on a path the specification does not "
                        "declare it for"
                        if parametric
                        else f", while the same method on random paths under the same parent "
                        f"({point.pattern}) answered otherwise: this path treats {method} "
                        "specially"
                    )
                    + ", and the specification does not declare it here. Declare it or "
                    "block it (OWASP ASVS v5.0.0-4.1.4); whether it requires a credential or the "
                    "right role is judged by tests 1.1 and 2.1."
                ),
                # On a path with parameters nothing was compared (its siblings
                # are the same route): the 2xx is the observation, FIRM.
                confidence=Confidence.CERTAIN if served and not parametric else Confidence.FIRM,
            ),
            reference_responses=(point,),
        )

    def _clean_up(
        self,
        record: EvidenceRecord,
        path: str,
        client: SecurityClient,
        store: EvidenceStore,
        left_behind: list[str],
        *,
        parametric: bool,
    ) -> None:
        """
        Delete what a handled write surely created, or name it as not undone (rule 7).

        Only two things are surely new: the object a Location names, and the
        random path a PUT on a path with parameters wrote to. Anything else (a
        POST without Location, a PUT or PATCH on a real path, a DELETE) changed
        something this test cannot undo, and a DELETE on a real path, sent
        without a credential after an accepted write, could remove a real
        resource: it is named, never deleted.

        Args:
            record:      The answer of the handled write.
            path:        The path probed.
            client:      The HTTP client.
            store:       The evidence store.
            left_behind: Filled with what was not undone.
            parametric:  Whether the path was built from random values.
        """
        method = record.request_method
        if method not in _WRITE_METHODS:
            return
        location = record.response_headers.get(_LOCATION_HEADER)
        created = location or (path if method == "PUT" and parametric else None)
        if created is None:
            left_behind.append(f"{method} {path}")
            return
        target_path = (
            "/" + created.split("://", 1)[-1].split("/", 1)[-1] if "://" in created else created
        )
        try:
            _response, removal = client.request("DELETE", target_path, test_id=self.info.id)
        except SecurityClientError:
            left_behind.append(target_path)
            return
        self._step(removal)
        if category_of(removal) not in (
            ResponseCategory.SERVED,
            ResponseCategory.NOT_FOUND,
        ):
            left_behind.append(target_path)
        store.pin_evidence(removal)

    # ------------------------------------------------------------------
    # Sub-test: undocumented_versions
    # ------------------------------------------------------------------

    def _versions(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[InfoNote]:
        """
        Probe one documented path under each undocumented version (rule 5).

        The candidates are the facts of the derivation rule version_siblings
        (Phase 2). The path probed under a sibling version is chosen by a
        stated rule: of that version group, a GET path first (read-only), a
        path of any documented method otherwise, preferring one without
        parameters and then the shortest. A method with a body is sent with an
        empty one: the question is whether the version directory answers, and
        an empty body creates nothing. Probing GET only left crAPI's
        /identity/api/auth/ group (every path a POST) unverifiable, which is
        where the methodology's own case lives (an older version of check-otp
        without the controls of the newer one).

        Args:
            target:  The run's target (derived facts, surface).
            context: The run's context (references).
            client:  The HTTP client.
            store:   The evidence store.

        Returns:
            The note listing what was probed, when anything was.
        """
        surface = target.attack_surface
        if surface is None:
            return []
        facts = surface.derived_facts(RULE_VERSION_SIBLINGS)
        if not facts:
            self._record(_SUB_VERSIONS, Outcome.NOT_APPLICABLE, "NO_VERSIONED_PATH")
            return []
        probed: list[str] = []
        for fact in facts:
            base, _, version = fact.value.rpartition("/")
            sample = self._version_sample(surface.endpoints, base)
            if sample is None:
                self._record(_SUB_VERSIONS, Outcome.NOT_APPLICABLE, "NO_PATH_IN_GROUP")
                continue
            endpoint, suffix = sample
            path = f"{base}/{version}{suffix}"
            concrete = self._concrete_path(path, endpoint)
            self._probe_version(concrete, endpoint.method, fact.value, context, client, store)
            probed.append(f"{endpoint.method} {concrete}")
        if not probed:
            return []
        return [
            InfoNote(
                title=f"{len(probed)} undocumented version(s) probed",
                detail=(
                    "The versions next to those the specification documents, from the "
                    f"derivation rule {RULE_VERSION_SIBLINGS}: "
                    f"{', '.join(probed[:_NOTE_EXAMPLES])}"
                    + (
                        f" and {len(probed) - _NOTE_EXAMPLES} more"
                        if len(probed) > _NOTE_EXAMPLES
                        else ""
                    )
                    + "."
                ),
            )
        ]

    @staticmethod
    def _version_sample(
        endpoints: list[EndpointRecord], base: str
    ) -> tuple[EndpointRecord, str] | None:
        """
        The documented path a version group lends for the probe, and its suffix.

        Chosen by the stated rule of the sub-test: a GET path first, then one
        without parameters, then the shortest.

        Args:
            endpoints: The surface's endpoints.
            base:      The path before the version segment, e.g. "/identity/api".

        Returns:
            (the endpoint, the path after the version segment), or None when the
            group documents no operation.
        """
        found: list[tuple[int, int, int, EndpointRecord, str]] = []
        for endpoint in endpoints:
            segments = endpoint.path.split("/")
            for position, segment in enumerate(segments):
                if _VERSION_SEGMENT.match(segment) and "/".join(segments[:position]) == base:
                    suffix = "/" + "/".join(segments[position + 1 :])
                    not_get = 0 if endpoint.method == "GET" else 1
                    parametric = 1 if _TEMPLATE_PARAMETER.search(suffix) else 0
                    found.append((not_get, parametric, len(suffix), endpoint, suffix))
                    break
        if not found:
            return None
        *_ranking, endpoint, suffix = min(found, key=lambda item: item[:3])
        return endpoint, suffix

    def _probe_version(  # noqa: PLR0913 -- one probe needs all of it
        self,
        path: str,
        method: str,
        candidate: str,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> None:
        """
        Request one path under an undocumented version and judge it (rule 3).

        Args:
            path:      The concrete path under the undocumented version.
            method:    The method the specification declares on that path; a
                       method with a body is sent with an empty one.
            candidate: The version directory the rule derived.
            context:   The run's context (references).
            client:    The HTTP client.
            store:     The evidence store.
        """
        body = _EMPTY_BODY if method in _BODY_METHODS else None
        try:
            _response, record = client.request(method, path, test_id=self.info.id, json=body)
        except SecurityClientError as exc:
            if exc.record is None:
                raise
            self._judge(exc.record, store, _SUB_VERSIONS, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return
        category = category_of(record)
        detail = _SPOILING.get(category)
        if detail is not None:
            self._judge(record, store, _SUB_VERSIONS, Outcome.NOT_VERIFIABLE, detail)
            return
        references = context.references
        similarity = references.same_as_unknown(record, template_path=path)
        point = references.calibration(sibling_pattern(path), method)
        if similarity == Similarity.UNRELIABLE:
            self._judge(
                record, store, _SUB_VERSIONS, Outcome.NOT_VERIFIABLE, "CALIBRATION_UNSTABLE"
            )
            return
        if similarity == Similarity.SAME_AS_UNKNOWN and category in _REFUSING:
            # The same refusal as any unknown path (crAPI's identity service
            # answers 401 to every path): the target refused before routing, so
            # whether the version exists is not known, as for the methods above.
            self._judge(
                record, store, _SUB_VERSIONS, Outcome.NOT_VERIFIABLE, "REFUSED_BEFORE_ROUTING"
            )
            return
        if similarity == Similarity.SAME_AS_UNKNOWN or category == ResponseCategory.NOT_FOUND:
            self._judge(record, store, _SUB_VERSIONS, Outcome.ENFORCED, "VERSION_ABSENT")
            return
        self._judge(
            record,
            store,
            _SUB_VERSIONS,
            Outcome.VIOLATION,
            "UNDOCUMENTED_VERSION",
            finding=Finding(
                title=f"Undocumented API version answers: {method} {path}",
                detail=(
                    f"{method} {path} (no credential) answered {record.response_status_code} "
                    f"({category.value}), unlike random paths under the same parent: the version "
                    f"directory {candidate} is not documented, while its neighbours are. An old "
                    "version left active lacks the controls added later; remove it or document "
                    "it. Whether two versions enforce the same controls is judged by test 2.4."
                ),
                # The candidate comes from a heuristic rule (rule 6, TENTATIVE).
                confidence=Confidence.TENTATIVE,
            ),
            reference_responses=(point,),
        )

    # ------------------------------------------------------------------
    # Sub-test: gateway_route_drift
    # ------------------------------------------------------------------

    def _routes(self, target: TargetContext, store: EvidenceStore) -> list[InfoNote]:
        """
        Compare the gateway's routes with the documented paths (optional need).

        Args:
            target: The run's target (gateway, surface).
            store:  The evidence store.

        Returns:
            No note: the judgements carry the sub-test's outcome.
        """
        if target.gateway is None:
            self._record(_SUB_ROUTES, Outcome.NOT_APPLICABLE, "NO_GATEWAY")
            return []
        answer = target.gateway.routes()
        evidence_ref = self._record_gateway_concept(target, store, CONCEPT_ROUTES, answer)
        if answer.status != ConceptStatus.READ:
            detail = (
                "ROUTES_NOT_SUPPORTED"
                if answer.status == ConceptStatus.NOT_SUPPORTED
                else "ROUTES_NOT_READABLE"
            )
            outcome = (
                Outcome.NOT_APPLICABLE
                if answer.status == ConceptStatus.NOT_SUPPORTED
                else Outcome.NOT_VERIFIABLE
            )
            self._record(_SUB_ROUTES, outcome, detail)
            return []
        surface = target.attack_surface
        documented = sorted({e.path for e in surface.endpoints} if surface is not None else set())
        spec_path = urlsplit(str(target.openapi_spec_url)).path if target.openapi_spec_url else None
        for route in answer.items:
            if not route.enabled:
                self._record(_SUB_ROUTES, Outcome.NOT_APPLICABLE, "ROUTE_DISABLED")
                continue
            orphans = [p for p in route.paths if not _route_covers(p, documented, spec_path)]
            if not orphans:
                self._record(_SUB_ROUTES, Outcome.ENFORCED, "ROUTE_DOCUMENTED")
                continue
            self._record(
                _SUB_ROUTES,
                Outcome.VIOLATION,
                "ROUTE_NOT_DOCUMENTED",
                Finding(
                    title=f"Gateway route without documented paths: {route.name}",
                    detail=(
                        f"The gateway's route '{route.name}' is enabled and exposes "
                        f"{', '.join(f'{p.value} ({p.match.value})' for p in orphans)}, under "
                        "which the specification documents no "
                        f"operation (backend: {route.backend or 'unknown'}). Either the route "
                        "exposes an API nobody reviewed, or it is left over from a removed one: "
                        "remove it or document what it serves."
                    ),
                    evidence_ref=evidence_ref,
                    # The configuration read: the observed fact itself (rule 6).
                    confidence=Confidence.CERTAIN,
                ),
            )
        return []


def _captured_by_a_template(declared: dict[str, set[str]]) -> frozenset[str]:
    """
    The documented paths without parameters whose random siblings another route captures.

    /users/search has the random siblings /users/<random>, which /users/{id}
    answers when it is documented: the comparison would set two routes against
    each other (_probe_method, sibling_captured).

    Args:
        declared: The documented paths and their methods.

    Returns:
        The paths without parameters next to a documented path that has a
        single parameter in place of their last segment.
    """
    parametric_last = {
        template.rsplit("/", 1)[0]
        for template in declared
        if _TEMPLATE_PARAMETER.fullmatch(template.rsplit("/", 1)[-1])
    }
    return frozenset(
        template
        for template in declared
        if not _TEMPLATE_PARAMETER.search(template)
        and template.rsplit("/", 1)[0] in parametric_last
    )


def _route_covers(route_path: RoutePath, documented: list[str], spec_path: str | None) -> bool:
    """
    Whether a route's path has a documented path (or the specification) under it.

    How the gateway matches the path is the adapter's answer (RouteMatch), so
    this comparison knows nothing about any gateway's own syntax.

    Args:
        route_path: One path of the gateway's route, with its match kind.
        documented: The documented paths.
        spec_path:  The path the specification is served at, if any.

    Returns:
        True when at least one documented path falls under the route.
    """
    candidates = [*documented, *([spec_path] if spec_path else [])]
    if route_path.match == RouteMatch.REGEX:
        try:
            expression = re.compile(route_path.value)
        except re.error:
            return False
        # A template is not a path a regex can match (/users/{id} against
        # ^/users/\d+$): it is tried as written and with a number and a word in
        # place of its parameters.
        instances = [
            _TEMPLATE_PARAMETER.sub(sample, path)
            for path in candidates
            for sample in _REGEX_PARAMETER_SAMPLES
        ]
        return any(expression.search(path) for path in [*candidates, *instances])
    if route_path.match == RouteMatch.EXACT:
        # A path matched exactly is covered by a documented operation on it, or
        # by the documented operations under it: an exact route of a directory
        # (APISIX writes /api beside /api/*) is their parent, and test
        # ext.0.1.ffuf does not judge such a parent either.
        under = route_path.value.rstrip("/") + "/"
        return any(path == route_path.value or path.startswith(under) for path in candidates)
    return any(path.startswith(route_path.value) for path in candidates)
