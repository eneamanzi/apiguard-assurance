"""
src/tests/domain_0/test_0_2_paths_without_a_route.py

Test 0.2: guarantee "the gateway answers a path it has no route for itself,
instead of forwarding it".

What is forwarded without a route reaches a backend without the policies the
gateway attaches to its routes (authentication, rate limiting, request
signing), because those are configured per route.

Two sub-tests:

    unrouted_paths     what the gateway answers where no route matches at all,
                       and whether that answer can be trusted as the gateway's
                       own;
    near_route_paths   a path just outside each route path, which is where a
                       gateway matching route paths as plain strings forwards
                       (optional need GATEWAY: without the routes this
                       sub-test is NOT_APPLICABLE and the other one runs).

How the two are told apart, without any list of gateway names. The old test
classified a response as a backend's when its Server header held no known
gateway name; measured on the labs (2026-10-22) neither Kong sends a Server
header at all and APISIX sends "APISIX", so the check was unreliable in both
directions. Instead the gateway's own refusal is measured at run time
(ReferenceResponses.gateway_refusal: two random paths at the root), and a
candidate answering differently was answered by something else, because with
no route matched the gateway has no other answer to give.

That reasoning needs one guard: if the backend's own "not here" answer looked
exactly like the gateway's refusal, a forwarded path would be indistinguishable
from a refused one and the test would claim a PASS it had not verified. So the
calibration of a documented parent is compared with the refusal first, and when
the two cannot be told apart the test says so instead.

What counts as a path the gateway has no route for: a path that is neither
equal to nor, segment by segment, under any route path. A route path matched as
a plain string (RouteMatch.PREFIX) also matches its neighbours (Kong's route
"/api" matches "/api-docs"), so those neighbours are exactly the candidates:
the route registers more paths than the API documents, which is CWE-183, a list
of allowed inputs that is too permissive.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base.
"""

from __future__ import annotations

import re

import structlog

from src.core.assessment_test import CONCEPT_NOT_ACCESSIBLE, category_of
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.gateway.base import CONCEPT_ROUTES
from src.core.gateway.concepts import ConceptStatus, GatewayRoute, RouteMatch, RoutePath
from src.core.models import (
    Confidence,
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
from src.core.references import (
    CalibrationPoint,
    fingerprint_of,
    random_token,
    sibling_pattern,
)
from src.core.response_category import categorize
from src.core.test_metadata import Effect, Need, OracleCase, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The sub-tests, in the order the page lists them.
_SUB_UNROUTED: str = "unrouted_paths"
_SUB_NEAR: str = "near_route_paths"

# How many neighbours a route path gets, by how the gateway matches it: a path
# matched as a plain string is the case at risk and gets every shape, an exact
# path gets one (a cheap check that the gateway is not more tolerant than its
# configuration says). A regex cannot be turned into a neighbouring path
# without interpreting it, so it gets none.
_NEIGHBOURS_BY_MATCH: dict[RouteMatch, int] = {
    RouteMatch.PREFIX: 3,
    RouteMatch.EXACT: 1,
    RouteMatch.REGEX: 0,
}

# The shapes of a neighbour, in the order they are used: the separators a
# segment-wise matcher stops at and a plain-string matcher does not.
_NEIGHBOUR_JOINS: tuple[str, ...] = ("-", "", ".")

# At most this many route paths are probed. The sampling rule takes the
# shortest path of every first segment first (see _sample), because the
# shortest path of a group is the one whose neighbours are most likely to be
# forwarded. Not a parameter: an operator has no reason to tune it (owner,
# 2026-10-22).
_MAX_ROUTE_PATHS: int = 50

# How many documented paths are tried for the backend's own refusal before the
# guard gives up.
_BACKEND_REFUSAL_TRIES: int = 3

# The categories in which the answer refuses the request itself. Such an
# answer says nothing about what is behind it: the policy of the over-matched
# route may have stopped the request at the gateway, or a backend may have
# refused it after being reached.
_REFUSING: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.UNAUTHENTICATED, ResponseCategory.FORBIDDEN}
)

# How many items a note lists by name.
_NOTE_EXAMPLES: int = 12

_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.NIST_SP, id="800-228", section="3.2.1"),
)

_ORACLE: tuple[OracleCase, ...] = (
    OracleCase(
        sub_test=_SUB_UNROUTED,
        when="the gateway's refusal at random root paths differs from a backend's own refusal",
        outcome=Outcome.ENFORCED,
        detail="REFUSED_BY_GATEWAY",
    ),
    OracleCase(
        sub_test=_SUB_UNROUTED,
        when="a random path at the root is served (`2xx`)",
        outcome=Outcome.VIOLATION,
        detail="SERVED_WITHOUT_ROUTE",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_UNROUTED,
        when="the two random root paths answered differently",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="REFUSAL_UNSTABLE",
    ),
    OracleCase(
        sub_test=_SUB_UNROUTED,
        when="an enabled route covers every path (a `/` prefix, a regex matching a random root "
        "path, or no path at all)",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="CATCH_ALL_ROUTE",
    ),
    OracleCase(
        sub_test=_SUB_UNROUTED,
        when="none of the shortest documented paths gives a reliable backend refusal",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="BACKEND_REFUSAL_UNKNOWN",
    ),
    OracleCase(
        sub_test=_SUB_UNROUTED,
        when="the gateway's refusal has the backend refusal's fingerprint",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="REFUSALS_INDISTINGUISHABLE",
    ),
    OracleCase(
        sub_test=_SUB_NEAR,
        when="a neighbour of a route path (outside it by whole segments) is served (`2xx`)",
        outcome=Outcome.VIOLATION,
        detail="SERVED_WITHOUT_ROUTE",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_NEAR,
        when="a neighbour answers unlike the gateway's refusal, neither `2xx` nor `401`, `403`",
        outcome=Outcome.VIOLATION,
        detail="ANSWERED_WITHOUT_ROUTE",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_NEAR,
        when="no neighbour answered, and one got the gateway's refusal",
        outcome=Outcome.ENFORCED,
        detail="REFUSED_BY_GATEWAY",
    ),
    OracleCase(
        sub_test=_SUB_NEAR,
        when="no neighbour answered or got the gateway's refusal, and one was refused (`401`, "
        "`403`)",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="REFUSED_BEFORE_ROUTING",
    ),
    OracleCase(
        sub_test=_SUB_NEAR,
        when="every neighbour is documented or covered by a route segment by segment",
        outcome=Outcome.NOT_APPLICABLE,
        detail="COVERED_BY_ROUTE",
    ),
    OracleCase(
        sub_test=_SUB_NEAR,
        when="the route path is a regular expression",
        outcome=Outcome.NOT_APPLICABLE,
        detail="REGEX_ROUTE_PATH",
    ),
    OracleCase(
        sub_test=_SUB_NEAR,
        when="the gateway's refusal is not trusted (`unrouted_paths` not ENFORCED)",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="REFUSAL_NOT_TRUSTED",
    ),
    OracleCase(
        sub_test=_SUB_NEAR,
        when="no gateway configured",
        outcome=Outcome.NOT_APPLICABLE,
        detail="NO_GATEWAY",
    ),
    OracleCase(
        sub_test=_SUB_NEAR,
        when="the gateway's adapter does not read routes",
        outcome=Outcome.NOT_APPLICABLE,
        detail="ROUTES_NOT_SUPPORTED",
    ),
    OracleCase(
        sub_test=_SUB_NEAR,
        when="the gateway has routes, and they could not be read",
        outcome=Outcome.NOT_VERIFIABLE,
        detail=CONCEPT_NOT_ACCESSIBLE,
    ),
)


class Test02PathsWithoutARoute(BaseTest):
    """
    Test 0.2 -- whether anything answers a path the gateway has no route for.

    The oracle of each sub-test is in the module docstring and on the test
    page.
    """

    info = TestInfo(
        id="0.2",
        name="Paths Without a Route",
        priority=0,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-183",
        references=_REFERENCES,
        tags=("inventory", "gateway-routing"),
        optional_needs=(Need.GATEWAY,),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_UNROUTED, _SUB_NEAR),
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
        Measure the gateway's refusal, then judge the paths around its routes.

        Args:
            target:  The run's target (surface, gateway).
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
            refusal = context.references.gateway_refusal()
            guard = self._unrouted(target, context, refusal)
            if guard is None:
                if target.gateway is None:
                    self._record(_SUB_NEAR, Outcome.NOT_APPLICABLE, "NO_GATEWAY")
                else:
                    self._record(_SUB_NEAR, Outcome.NOT_VERIFIABLE, "REFUSAL_NOT_TRUSTED")
                return self._finish(notes=notes)
            notes += self._near_routes(target, client, store, (refusal, guard))
            return self._finish(notes=notes)
        except SecurityClientError as exc:
            return self._error(exc)

    # ------------------------------------------------------------------
    # Sub-test 1: what the gateway answers where no route matches
    # ------------------------------------------------------------------

    def _unrouted(
        self, target: TargetContext, context: TestContext, refusal: CalibrationPoint
    ) -> CalibrationPoint | None:
        """
        Judge the gateway's refusal itself and say whether it can be trusted.

        The refusal is measured by the reference responses on two random paths
        at the root, so those two requests are this sub-test's probes: what
        they answer is what the gateway does where nothing matches.

        Args:
            target:  The run's target (gateway, surface).
            context: The run's context (reference responses).
            refusal: The measured refusal.

        Returns:
            The backend's own refusal (the guard) when the other sub-test may
            rest on the gateway's refusal, which it then cites with it (rule 6); None otherwise.
        """
        if not refusal.reliable:
            self._record(_SUB_UNROUTED, Outcome.NOT_VERIFIABLE, "REFUSAL_UNSTABLE")
            return None
        fingerprint = refusal.fingerprint
        if fingerprint is None:
            self._record(_SUB_UNROUTED, Outcome.NOT_VERIFIABLE, "REFUSAL_UNSTABLE")
            return None
        catch_all = _catch_all_route(target)
        if catch_all is not None:
            self._record(_SUB_UNROUTED, Outcome.NOT_VERIFIABLE, "CATCH_ALL_ROUTE")
            log.info("test_0_2_catch_all_route", route=catch_all)
            return None
        category = categorize(fingerprint.status_code)
        if category == ResponseCategory.SERVED:
            self._record(
                _SUB_UNROUTED,
                Outcome.VIOLATION,
                "SERVED_WITHOUT_ROUTE",
                Finding(
                    title="A path with no route is served",
                    detail=(
                        "A random path at the root, which matches none of the gateway's routes, "
                        f"answered HTTP {fingerprint.status_code}. Something behind the gateway "
                        "served it, so the gateway forwards what it has no route for and the "
                        "policies attached to its routes do not apply. Either a route covers more "
                        "than it should, or a default backend answers what no route matched."
                    ),
                    evidence_ref=refusal.record_ids[0],
                    supporting_refs=list(refusal.record_ids[1:]),
                    confidence=Confidence.CERTAIN,
                ),
            )
            return None
        uninformative = self._uninformative_category(category, _SUB_UNROUTED)
        if uninformative is not None:
            self._record(_SUB_UNROUTED, Outcome.NOT_VERIFIABLE, uninformative)
            return None
        backend = self._backend_refusal(target, context)
        if backend is None:
            self._record(_SUB_UNROUTED, Outcome.NOT_VERIFIABLE, "BACKEND_REFUSAL_UNKNOWN")
            return None
        if backend.fingerprint == fingerprint:
            self._record(_SUB_UNROUTED, Outcome.NOT_VERIFIABLE, "REFUSALS_INDISTINGUISHABLE")
            return None
        self._record(_SUB_UNROUTED, Outcome.ENFORCED, "REFUSED_BY_GATEWAY")
        return backend

    def _backend_refusal(
        self, target: TargetContext, context: TestContext
    ) -> CalibrationPoint | None:
        """
        The fingerprint of a backend's own "not here" answer, for the guard.

        Taken from the calibration of a documented path's siblings: that answer
        comes from behind the gateway, where a route does match. The documented
        paths are tried shortest first, deterministically, until one has a
        reliable calibration.

        Args:
            target:  The run's target (surface).
            context: The run's context (reference responses).

        Returns:
            The calibration point, or None when no documented path could give one.
        """
        surface = target.attack_surface
        if surface is None:
            return None
        paths = sorted({e.path for e in surface.endpoints}, key=lambda p: (len(p), p))
        for path in paths[:_BACKEND_REFUSAL_TRIES]:
            parameters = next(
                (e.parameters for e in surface.endpoints if e.path == path),
                (),
            )
            point = context.references.calibration(sibling_pattern(path, parameters))
            if point.reliable and point.fingerprint is not None:
                return point
        return None

    # ------------------------------------------------------------------
    # Sub-test 2: the paths just outside each route path
    # ------------------------------------------------------------------

    def _near_routes(
        self,
        target: TargetContext,
        client: SecurityClient,
        store: EvidenceStore,
        references: tuple[CalibrationPoint, CalibrationPoint],
    ) -> list[InfoNote]:
        """
        Probe the neighbours of each route path (optional need).

        Args:
            target:     The run's target (gateway, surface).
            client:     The run's HTTP client.
            store:      The evidence store.
            references: The gateway's measured refusal, already trusted, and
                        the backend's own refusal that made it trusted.

        Returns:
            A note on what could not be interpreted, when there is one.
        """
        if target.gateway is None:
            self._record(_SUB_NEAR, Outcome.NOT_APPLICABLE, "NO_GATEWAY")
            return []
        answer = target.gateway.routes()
        self._record_gateway_concept(target, store, CONCEPT_ROUTES, answer)
        if answer.status == ConceptStatus.NOT_SUPPORTED:
            self._record(_SUB_NEAR, Outcome.NOT_APPLICABLE, "ROUTES_NOT_SUPPORTED")
            return []
        if answer.status != ConceptStatus.READ:
            # The shared rule (until 2026-11-16 ROUTES_NOT_READABLE).
            self._record(_SUB_NEAR, Outcome.NOT_VERIFIABLE, CONCEPT_NOT_ACCESSIBLE)
            return []
        routes = [r for r in answer.items if r.enabled]
        surface = target.attack_surface
        documented = {e.path for e in surface.endpoints} if surface is not None else set()
        regex_paths: list[str] = []
        for route, route_path in _sample(routes):
            wanted = _NEIGHBOURS_BY_MATCH[route_path.match]
            if wanted == 0:
                regex_paths.append(route_path.value)
                self._record(_SUB_NEAR, Outcome.NOT_APPLICABLE, "REGEX_ROUTE_PATH")
                continue
            self._probe_route_path(
                client, store, references, route, route_path, wanted, routes, documented
            )
        notes: list[InfoNote] = []
        if regex_paths:
            shown = ", ".join(regex_paths[:_NOTE_EXAMPLES])
            notes.append(
                InfoNote(
                    title="Route paths matched by a regular expression",
                    detail=(
                        f"{len(regex_paths)} route path(s) are matched by a regular expression, "
                        "which this test does not interpret: no neighbour was built for them, and "
                        "a path counted here as having no route may be matched by one of them "
                        f"({shown})."
                    ),
                )
            )
        return notes

    def _probe_route_path(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        references: tuple[CalibrationPoint, CalibrationPoint],
        route: GatewayRoute,
        route_path: RoutePath,
        wanted: int,
        routes: list[GatewayRoute],
        documented: set[str],
    ) -> None:
        """
        Judge one route path by asking the paths just outside it.

        One judgement per route path, not per probe: the neighbours are
        several proofs of the same fact, that the route matches more than the
        segments of its path. The first proof of something answering decides
        and the rest are not sent; the other probes are logged as steps.

        Args:
            client:     The run's HTTP client.
            store:      The evidence store.
            references: The gateway's measured refusal and the backend's (the
                        guard); a finding cites both.
            route:      The route.
            route_path: The path of it being judged.
            wanted:     How many neighbours its match type deserves.
            routes:     Every enabled route, to leave covered paths alone.
            documented: The documented paths, to leave them alone.
        """
        refusal = references[0]
        seen: list[tuple[EvidenceRecord | None, str]] = []
        for join in _NEIGHBOUR_JOINS[:wanted]:
            token = random_token()
            path = route_path.value.rstrip("/") + join + token
            if path in documented or _covered_by_segments(path, routes):
                seen.append((None, "COVERED_BY_ROUTE"))
                continue
            record = self._ask(client, path)
            category = category_of(record)
            if category == ResponseCategory.SERVED:
                self._judge(
                    record,
                    store,
                    _SUB_NEAR,
                    Outcome.VIOLATION,
                    "SERVED_WITHOUT_ROUTE",
                    self._finding(route, route_path, path, record, served=True),
                    reference_responses=references,
                )
                return
            if category in _REFUSING:
                # An answer that refuses the request says nothing about what is
                # behind it: the gateway's own policy on the over-matched route
                # may have stopped it (Kong's hmac-auth plugin answers 401 on
                # every path its route matches, measured 2026-10-22), or a
                # backend may have. Not a violation, and not a pass.
                seen.append((record, "REFUSED_BEFORE_ROUTING"))
                continue
            uninformative = self._uninformative(record, _SUB_NEAR)
            if uninformative is not None:
                seen.append((record, uninformative))
                continue
            if fingerprint_of(record, (token,)) == refusal.fingerprint:
                seen.append((record, "REFUSED_BY_GATEWAY"))
                continue
            self._judge(
                record,
                store,
                _SUB_NEAR,
                Outcome.VIOLATION,
                "ANSWERED_WITHOUT_ROUTE",
                self._finding(route, route_path, path, record, served=False),
                reference_responses=references,
            )
            return
        self._conclude(store, seen)

    def _conclude(
        self, store: EvidenceStore, seen: list[tuple[EvidenceRecord | None, str]]
    ) -> None:
        """
        Record the verdict of a route path whose neighbours proved nothing.

        The best news wins: a neighbour the gateway refused with its own answer
        is the guarantee holding, a refusal before routing is not verifiable,
        and a path no probe could be built for is not applicable.

        Args:
            store: The evidence store.
            seen:  What each neighbour answered, in order.
        """
        for wanted_detail, outcome in (
            ("REFUSED_BY_GATEWAY", Outcome.ENFORCED),
            ("REFUSED_BEFORE_ROUTING", Outcome.NOT_VERIFIABLE),
        ):
            for record, detail in seen:
                if detail == wanted_detail and record is not None:
                    self._judge(record, store, _SUB_NEAR, outcome, detail)
                    return
        for record, detail in seen:
            if record is not None:
                self._judge(record, store, _SUB_NEAR, Outcome.NOT_VERIFIABLE, detail)
                return
        self._record(_SUB_NEAR, Outcome.NOT_APPLICABLE, "COVERED_BY_ROUTE")

    def _ask(self, client: SecurityClient, path: str) -> EvidenceRecord:
        """
        Ask one path, keeping the record of a transport failure.

        Args:
            client: The run's HTTP client.
            path:   The path to ask.

        Returns:
            The record of the answer, or of the failure.

        Raises:
            SecurityClientError: A failure with no record at all.
        """
        try:
            _response, record = client.request("GET", path, test_id=self.info.id)
        except SecurityClientError as exc:
            if exc.record is None:
                raise
            return exc.record
        return record

    def _finding(
        self,
        route: GatewayRoute,
        route_path: RoutePath,
        path: str,
        record: EvidenceRecord,
        *,
        served: bool,
    ) -> Finding:
        """
        The finding of a path answered although no route covers it.

        Args:
            route:      The route the path sits next to.
            route_path: Its path and how the gateway matches it.
            path:       The path asked.
            record:     Its answer.
            served:     True when the answer was a success (2xx).

        Returns:
            The Finding; _judge sets its evidence_ref.
        """
        who = (
            "was served by something behind the gateway"
            if served
            else "was answered by something other than the gateway, whose own answer where no "
            "route matches has a different shape"
        )
        return Finding(
            title=f"Answered without a route: GET {path}",
            detail=(
                f"The path {path} is not equal to and not under any of the gateway's route paths, "
                f"segment by segment, yet it answered HTTP {record.response_status_code} and {who}"
                f". It sits next to the route '{route.name}', whose path {route_path.value} the "
                f"gateway matches as {route_path.match.value} (backend: "
                f"{route.backend or 'unknown'}): that route therefore registers more paths than "
                "the API documents: paths of the backend outside the route's documented scope are "
                "reachable through it (with the route's own policies). Match the route path by "
                "whole segments, or make it exact."
            ),
            confidence=Confidence.CERTAIN if served else Confidence.FIRM,
        )


def _sample(routes: list[GatewayRoute]) -> list[tuple[GatewayRoute, RoutePath]]:
    """
    The route paths to probe, by the sampling rule, with their route.

    The paths are grouped by their first segment and taken group by group,
    shortest of each group first, up to _MAX_ROUTE_PATHS: the shortest path of
    a group is the one whose neighbours are most likely to be forwarded.

    Args:
        routes: The enabled routes.

    Returns:
        Pairs of (route, route path), at most _MAX_ROUTE_PATHS of them.
    """
    groups: dict[str, list[tuple[GatewayRoute, RoutePath]]] = {}
    for route in routes:
        for route_path in route.paths:
            first = route_path.value.lstrip("/").split("/", 1)[0]
            groups.setdefault(first, []).append((route, route_path))
    for group in groups.values():
        group.sort(key=lambda pair: (len(pair[1].value), pair[1].value))
    ordered = sorted(groups.items(), key=lambda item: (len(item[1][0][1].value), item[0]))
    taken: list[tuple[GatewayRoute, RoutePath]] = []
    round_index = 0
    while len(taken) < _MAX_ROUTE_PATHS:
        added = False
        for _, group in ordered:
            if round_index < len(group):
                taken.append(group[round_index])
                added = True
                if len(taken) == _MAX_ROUTE_PATHS:
                    break
        if not added:
            break
        round_index += 1
    return taken


def _covered_by_segments(path: str, routes: list[GatewayRoute]) -> bool:
    """
    Whether a route path covers this path when matched by whole segments.

    A regex route path is not interpreted, so it covers nothing here; the note
    of the sub-test says which ones those were.

    Args:
        path:   The path asked.
        routes: The enabled routes.

    Returns:
        True when a route path is equal to the path or is a segment-wise
        parent of it.
    """
    for route in routes:
        for route_path in route.paths:
            if route_path.match == RouteMatch.REGEX:
                continue
            value = route_path.value.rstrip("/")
            if path == value:
                return True
            if route_path.match == RouteMatch.PREFIX and path.startswith(value + "/"):
                return True
    return False


def _catch_all_route(target: TargetContext) -> str | None:
    """
    The name of a route that covers every path, when there is one.

    A route path "/" matched as a plain string registers every path, so no path
    is left for the test to ask about and deny-by-default cannot be probed. So
    does a regex route path that matches a random path at the root, the shape of
    the probes that measure the gateway's refusal: with a route `~/.*$` those
    probes reach the backend, its answer is taken for the gateway's refusal and
    every forwarded neighbour looks refused (a PASS seen on 2026-11-15). The
    expression is tried as test 0.1 tries one (re.search); one that Python's re
    cannot compile is not interpreted.

    Args:
        target: The run's target (gateway).

    Returns:
        The route's name, or None.
    """
    if target.gateway is None:
        return None
    answer = target.gateway.routes()
    if answer.status != ConceptStatus.READ:
        return None
    root_probe = "/" + random_token()
    for route in answer.items:
        if not route.enabled:
            continue
        for route_path in route.paths:
            if route_path.match == RouteMatch.PREFIX and route_path.value.rstrip("/") == "":
                return route.name
            regex = route_path.match == RouteMatch.REGEX
            if regex and _regex_matches(route_path.value, root_probe):
                return route.name
    return None


def _regex_matches(expression: str, path: str) -> bool:
    """
    Whether a regex route path matches a path, as test 0.1 tries one.

    Args:
        expression: The route path's regular expression, as the adapter gives it.
        path:       The path tried.

    Returns:
        True when the expression compiles and is found in the path.
    """
    try:
        pattern = re.compile(expression)
    except re.error:
        return False
    return pattern.search(path) is not None
