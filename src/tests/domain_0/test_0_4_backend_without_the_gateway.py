"""
src/tests/domain_0/test_0_4_backend_without_the_gateway.py

Test 0.4: guarantee "a backend the gateway routes to answers only through the
gateway".

A backend that answers directly is reachable without any of the gateway's
policies, so every guarantee the other tests verify through the gateway can be
skipped. NIST SP 800-228 section 4.1 says it: a gateway at the perimeter "can
be bypassed (e.g., via an attacker pivoting inside the perimeter), which in
turn bypasses the policy checks that are enforced by that gateway".

One sub-test, backend_addresses. For every backend the gateway declares, two
candidate addresses are tried:

    the declared address      what the operator configured, as the gateway
                              states it (Kong gives a name and a port,
                              "forgejo:3000"; APISIX's Control API gives the
                              node already resolved, "172.21.0.4:3000");
    the target's own host      with that backend's port ("localhost:8443" and
    with the backend's port   "forgejo:3000" give "localhost:3000"): the common
                              case of a backend whose port is published on the
                              same machine as the gateway. Derived from what the
                              gateway says, not configured (rule 5).

The two are judged differently, and the reason is a measurement of 2026-10-22:
with the three labs running, "localhost:8000" (the host, and the port of
crAPI's workshop backend) answers, but what answers is the other lab's gateway,
not that backend. An HTTP answer at a port of the target's host is therefore
evidence only when it is the same answer the gateway gives for the same path;
an answer at the address the gateway itself declares is evidence either way,
because the gateway is what says the backend is there.

What the verdict is worth. It holds for the network the run started from and
says so: a name that does not resolve proves nothing about isolation, it only
says the tool is not on that network. The name is resolved by the test before
the request, because a client transport error cannot tell a refused connection
from a name that does not exist, and that difference is the whole difference
between "the backend refuses us" and "we are not there to ask".

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base.
"""

from __future__ import annotations

import socket
from urllib.parse import urlsplit

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.gateway.base import CONCEPT_TARGET_HEALTH
from src.core.gateway.concepts import ConceptStatus
from src.core.models import (
    Confidence,
    EvidenceRecord,
    Finding,
    Outcome,
    Reference,
    Standard,
    TestResult,
    TestStrategy,
    TransportError,
)
from src.core.references import Fingerprint, fingerprint_of
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The single sub-test.
_SUB_ADDRESSES: str = "backend_addresses"

# The schemes tried at a candidate address, in order: a backend behind a
# gateway usually speaks plain HTTP, and the second try is for one that does
# not (the first attempt then fails on TLS or on the protocol). Each attempt
# uses the run's own timeouts (target.timeouts, through the client).
_SCHEMES: tuple[str, ...] = ("http", "https")

# The transport errors that mean nothing was listening: the name had already
# been resolved, so the connection was refused or timed out.
_UNREACHABLE: frozenset[TransportError] = frozenset(
    {TransportError.CONNECTION_FAILED, TransportError.TIMEOUT}
)

# The transport errors that mean something was listening but its answer could
# not be read.
_SPOKE_BUT_UNREAD: frozenset[TransportError] = frozenset(
    {TransportError.TLS_ERROR, TransportError.PROTOCOL_ERROR}
)

_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.NIST_SP, id="800-228", section="4.1"),
)


class Candidate:
    """One address to try, and what counts as evidence there."""

    def __init__(self, backend: str, host: str, port: int, *, declared: bool) -> None:
        """
        Build a candidate address.

        Args:
            backend:  The backend's name as the gateway calls it.
            host:     The host or address to ask.
            port:     The port to ask.
            declared: True when the gateway states this address itself; False
                      when it is the target's own host with the backend's port.
        """
        self.backend = backend
        self.host = host
        self.port = port
        self.declared = declared

    @property
    def address(self) -> str:
        """The address as it is written in the result."""
        return f"{self.host}:{self.port}"


class Test04BackendWithoutTheGateway(BaseTest):
    """
    Test 0.4 -- whether a backend answers without passing through the gateway.

    The oracle is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="0.4",
        name="Backend Reachable Without the Gateway",
        priority=0,
        strategy=TestStrategy.WHITE_BOX,
        cwe="CWE-420",
        references=_REFERENCES,
        tags=("inventory", "gateway-routing"),
        needs=(Need.GATEWAY,),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_ADDRESSES,),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Ask the same documented path through the gateway and at every backend address.

        Args:
            target:  The run's target (surface, gateway, base URL).
            context: The run's context (unused: the comparison is the test's
                     own request through the gateway).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._skip() without an attack surface, or
            self._error(exc).
        """
        del context
        try:
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            probe_path = _probe_path(target)
            if probe_path is None:
                self._record(_SUB_ADDRESSES, Outcome.NOT_VERIFIABLE, "NO_PROBE_PATH")
                return self._finish()
            through = self._through_gateway(client, store, probe_path)
            if through is None:
                self._record(_SUB_ADDRESSES, Outcome.NOT_VERIFIABLE, "TARGET_NOT_ANSWERING")
                return self._finish()
            candidates = self._candidates(target, store)
            if candidates is None:
                return self._finish()
            if not candidates:
                self._record(_SUB_ADDRESSES, Outcome.NOT_VERIFIABLE, "NO_BACKEND_ADDRESS")
                return self._finish()
            for candidate in candidates:
                self._try(client, store, candidate, probe_path, through)
            return self._finish()
        except SecurityClientError as exc:
            return self._error(exc)

    # ------------------------------------------------------------------
    # What the gateway answers, as the comparison
    # ------------------------------------------------------------------

    def _through_gateway(
        self, client: SecurityClient, store: EvidenceStore, probe_path: str
    ) -> EvidenceRecord | None:
        """
        Ask the probe path through the gateway, as the answer to compare with.

        Args:
            client:     The run's HTTP client.
            store:      The evidence store.
            probe_path: The documented path asked.

        Returns:
            The record, or None when the target itself did not answer.
        """
        try:
            _response, record = client.request("GET", probe_path, test_id=self.info.id)
        except SecurityClientError as exc:
            if exc.record is not None:
                self._step(exc.record)
            return None
        self._step(record)
        return record

    # ------------------------------------------------------------------
    # The candidate addresses
    # ------------------------------------------------------------------

    def _candidates(self, target: TargetContext, store: EvidenceStore) -> list[Candidate] | None:
        """
        The addresses to try, from what the gateway declares.

        Args:
            target: The run's target (gateway, base URL).
            store:  The evidence store.

        Returns:
            The candidates, or None when the gateway could not be read (the
            judgement is already recorded).
        """
        gateway = target.gateway
        if gateway is None:
            self._record(_SUB_ADDRESSES, Outcome.NOT_APPLICABLE, "NO_GATEWAY")
            return None
        answer = gateway.target_health()
        self._record_gateway_concept(target, store, CONCEPT_TARGET_HEALTH, answer)
        if answer.status != ConceptStatus.READ:
            outcome = (
                Outcome.NOT_APPLICABLE
                if answer.status == ConceptStatus.NOT_SUPPORTED
                else Outcome.NOT_VERIFIABLE
            )
            self._record(_SUB_ADDRESSES, outcome, "ADDRESSES_NOT_READABLE")
            return None
        own = urlsplit(str(target.base_url))
        own_host = own.hostname or ""
        own_port = own.port
        candidates: list[Candidate] = []
        seen: set[tuple[str, int]] = set()
        for item in answer.items:
            parsed = _host_port(item.target)
            if parsed is None:
                self._record(_SUB_ADDRESSES, Outcome.NOT_VERIFIABLE, "ADDRESS_WITHOUT_PORT")
                continue
            host, port = parsed
            for candidate_host, declared in ((host, True), (own_host, False)):
                if not candidate_host:
                    continue
                if (candidate_host, port) == (own_host, own_port):
                    # The target itself: that is the gateway, not a way around it.
                    continue
                if (candidate_host, port) in seen:
                    continue
                seen.add((candidate_host, port))
                candidates.append(Candidate(item.backend, candidate_host, port, declared=declared))
        return candidates

    # ------------------------------------------------------------------
    # One candidate address
    # ------------------------------------------------------------------

    def _try(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        candidate: Candidate,
        probe_path: str,
        through: EvidenceRecord,
    ) -> None:
        """
        Resolve a candidate address, ask it the probe path and judge the answer.

        Args:
            client:     The run's HTTP client.
            store:      The evidence store.
            candidate:  The address to try.
            probe_path: The documented path asked.
            through:    What the same path answered through the gateway.
        """
        if not _resolves(candidate.host, candidate.port):
            self._record(_SUB_ADDRESSES, Outcome.NOT_VERIFIABLE, "ADDRESS_NOT_RESOLVABLE")
            log.info(
                "test_0_4_address_not_resolvable",
                backend=candidate.backend,
                address=candidate.address,
            )
            return
        record: EvidenceRecord | None = None
        for scheme in _SCHEMES:
            origin = f"{scheme}://{candidate.address}"
            try:
                _response, record = client.request(
                    "GET", probe_path, test_id=self.info.id, origin=origin
                )
            except SecurityClientError as exc:
                if exc.record is None:
                    raise
                record = exc.record
                if record.transport_error in _SPOKE_BUT_UNREAD:
                    continue
            break
        if record is None:
            self._record(_SUB_ADDRESSES, Outcome.NOT_VERIFIABLE, "NO_ATTEMPT")
            return
        self._judge_candidate(store, candidate, record, through)

    def _judge_candidate(
        self,
        store: EvidenceStore,
        candidate: Candidate,
        record: EvidenceRecord,
        through: EvidenceRecord,
    ) -> None:
        """
        Say what one candidate's answer means for the guarantee.

        Args:
            store:     The evidence store.
            candidate: The address tried.
            record:    Its answer, or the record of the failed attempt.
            through:   What the same path answered through the gateway.
        """
        failure = record.transport_error
        if failure in _UNREACHABLE:
            self._judge(record, store, _SUB_ADDRESSES, Outcome.ENFORCED, "BACKEND_UNREACHABLE")
            return
        if failure is not None and candidate.declared:
            self._judge(
                record,
                store,
                _SUB_ADDRESSES,
                Outcome.VIOLATION,
                "ADDRESS_ANSWERS_DIRECTLY",
                self._finding(candidate, record, same=False, unread=True),
            )
            return
        if failure is not None:
            self._judge(record, store, _SUB_ADDRESSES, Outcome.NOT_APPLICABLE, "ANOTHER_SERVICE")
            return
        same = _same_application(fingerprint_of(record), fingerprint_of(through))
        if same:
            self._judge(
                record,
                store,
                _SUB_ADDRESSES,
                Outcome.VIOLATION,
                "BACKEND_ANSWERS_DIRECTLY",
                self._finding(candidate, record, same=True, unread=False),
            )
            return
        if candidate.declared:
            self._judge(
                record,
                store,
                _SUB_ADDRESSES,
                Outcome.VIOLATION,
                "ADDRESS_ANSWERS_DIRECTLY",
                self._finding(candidate, record, same=False, unread=False),
            )
            return
        self._judge(record, store, _SUB_ADDRESSES, Outcome.NOT_APPLICABLE, "ANOTHER_SERVICE")

    def _finding(
        self,
        candidate: Candidate,
        record: EvidenceRecord,
        *,
        same: bool,
        unread: bool,
    ) -> Finding:
        """
        The finding of an address that answers without the gateway.

        Args:
            candidate: The address tried.
            record:    Its answer.
            same:      True when it answered as the gateway does for that path.
            unread:    True when it only opened a connection, its answer unread.

        Returns:
            The Finding; _judge sets its evidence_ref.
        """
        where = (
            "the address the gateway declares for it"
            if candidate.declared
            else "the target's own host with that backend's port"
        )
        if same:
            what = (
                f"it answered HTTP {record.response_status_code} with the same shape the gateway "
                "gives for the same path, so the same application answered without passing "
                "through the gateway"
            )
            confidence = Confidence.CERTAIN
        elif unread:
            what = (
                f"a connection opened and the answer could not be read "
                f"({record.transport_error}), so something is listening where the gateway says "
                "the backend is"
            )
            confidence = Confidence.FIRM
        else:
            what = (
                f"it answered HTTP {record.response_status_code}, not as the gateway answers for "
                "the same path, so something is listening where the gateway says the backend is"
            )
            confidence = Confidence.FIRM
        return Finding(
            title=f"Backend answers without the gateway: {candidate.address}",
            detail=(
                f"The gateway routes to the backend '{candidate.backend}'. Asked at "
                f"{candidate.address} ({where}) from where this run started, {what}. Every "
                "policy the gateway applies (authentication, rate limiting, request signing) is "
                "attached to its routes, so a caller reaching this address skips all of them. "
                "Let the backend accept traffic only from the gateway, with a network policy or "
                "a service-level authorization rule, and have it authenticate the gateway rather "
                "than trust its position. The verdict holds for the network this run started "
                "from."
            ),
            confidence=confidence,
        )


def _probe_path(target: TargetContext) -> str | None:
    """
    The documented path asked at every address, chosen by a stated rule.

    The shortest documented path with no parameters that the specification
    declares for GET, taking the alphabetically first of equal length so that
    two runs on one target ask the same path. A path with parameters is not
    used: filling it would ask about an object, not about the address.

    Args:
        target: The run's target (surface).

    Returns:
        The path, or None when the specification declares no such path.
    """
    surface = target.attack_surface
    if surface is None:
        return None
    paths = {e.path for e in surface.endpoints if e.method.upper() == "GET" and "{" not in e.path}
    if not paths:
        return None
    return sorted(paths, key=lambda p: (len(p), p))[0]


def _host_port(address: str) -> tuple[str, int] | None:
    """
    The host and port of an address the gateway states, e.g. "forgejo:3000".

    Args:
        address: The address as the gateway's concept gives it.

    Returns:
        (host, port), or None when there is no port to ask.
    """
    text = address.strip()
    if not text:
        return None
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0 or not text[closing + 1 :].startswith(":"):
            return None
        host, port_text = text[1:closing], text[closing + 2 :]
    elif ":" in text:
        host, port_text = text.rsplit(":", 1)
    else:
        return None
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not host or not 1 <= port <= 65535:
        return None
    return host, port


def _resolves(host: str, port: int) -> bool:
    """
    Whether the host has an address on the network this run started from.

    Asked before the request because a transport error cannot tell a refused
    connection from a name that does not exist, and the two mean opposite
    things for this guarantee.

    Args:
        host: The host or address.
        port: The port (the lookup is made for it).

    Returns:
        True when the name resolves.
    """
    try:
        socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    return True


def _same_application(direct: Fingerprint, through: Fingerprint) -> bool:
    """
    Whether two answers come from the same application.

    The status, the media type and the shape of the body are compared. The
    Server header is left out on purpose: a gateway sets or removes it (APISIX
    sends "APISIX", Kong on the labs sends none), so the same application
    answers with a different Server header through the gateway and without it.

    Args:
        direct:  The answer at the candidate address.
        through: The answer through the gateway.

    Returns:
        True when the two match.
    """
    return (direct.status_code, direct.content_type, direct.body_shape) == (
        through.status_code,
        through.content_type,
        through.body_shape,
    )
