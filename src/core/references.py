"""
src/core/references.py

Reference responses: what the target itself says, at run time, against which a
response is judged.

Two kinds, one object per run (ReferenceResponses, created by the engine and
reached through TestContext.references):

    calibration       what "does not exist here" looks like: two requests to
                      random siblings of the path being judged (its sibling
                      pattern: a path with parameters keeps its template with
                      random values in place of the parameters, of the type the
                      specification declares (integer, UUID, string), the answer
                      of an object that does not exist on the same route; a path
                      without parameters gets a random last segment), with the
                      same method and the same credential condition as the
                      judged request (none, or a credential the caller gives),
                      without a body. Asked once per (pattern, method,
                      credential label), kept for the run. Answers
                      same_as_unknown().
    positive control  whether the same request works with a valid credential
                      the caller gives (the test knows which role is right).
                      Asked once per (method, path, credential label).
                      Answers positive_control().
    gateway refusal   what the gateway answers when none of its routes matches:
                      two requests to random paths at the root, unauthenticated,
                      asked once for the run. Unlike a calibration point it has
                      no spoiling rule, because a refusal is exactly what is
                      being measured: a 401 or a 403 here is the gateway's own
                      answer, not a probe that says nothing. Answers
                      gateway_refusal(); the caller compares an answer with it
                      through fingerprint_of().

A judged response that is itself rate limited, unanswered or refused by an
unavailable upstream is not compared (UNRELIABLE). A calibration point is used
only when it is reliable: its two probes got the
same fingerprint, and neither was rate limited, unanswered or refused by an
unavailable upstream; otherwise every comparison with it is UNRELIABLE. The
random names start with a fixed neutral prefix that no route is expected to
match (a Kong route "/api" also matches "/apiguard..."; the spike of
2026-10-20).

response_facts() puts the status and the references together: the category
a test judges (the status's, with one correction, below) and whether the
endpoint is proven to exist. It is the first step of a judgement when the test
asked for references.

Every reference request is an EvidenceRecord with ID ref_NNN, pinned in the
evidence store of the test that asked first; summary() lists the points and
controls for the report.

The fingerprint compares status, content type, Server header and the shape of
the body (JSON: the keys at the first two levels; text: the first characters
with numbers, hexadecimal strings, UUIDs and the probed segments replaced), the
measure of the spike: 356 calibration points on three labs, no two random probes
of a point differed.

Dependency rule: imports only from the standard library, pydantic, structlog
and src.core (client, evidence, models, response_category).
"""

from __future__ import annotations

import json
import re
import secrets
import uuid
from collections.abc import Sequence
from enum import StrEnum

import structlog
from pydantic import BaseModel, Field

from src.core.client import SecurityClient
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.models import EvidenceRecord, ParameterInfo, ResponseCategory
from src.core.response_category import categorize

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The test_id under which the client numbers the reference requests: "ref_001".
REFERENCE_TEST_ID: str = "ref"

# The random sibling names: a fixed neutral prefix and random hex characters.
_PROBE_PREFIX: str = "zqxv"
_PROBE_RANDOM_BYTES: int = 6
_PROBES_PER_POINT: int = 2

# The sibling pattern of a path at the root: where the gateway refusal is probed.
_ROOT_PATTERN: str = "/{*}"

# Categories that spoil a calibration probe: the answer says nothing about
# whether a path exists.
_SPOILING_CATEGORIES: frozenset[ResponseCategory] = frozenset(
    {
        ResponseCategory.RATE_LIMITED,
        ResponseCategory.NO_RESPONSE,
        ResponseCategory.UPSTREAM_UNAVAILABLE,
    }
)

# Body normalization of the fingerprint.
_BODY_TEXT_CHARS: int = 200
_JSON_SHAPE_DEPTH: int = 2
_UUID_PATTERN: re.Pattern[str] = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)
_HEX_PATTERN: re.Pattern[str] = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
_NUMBER_PATTERN: re.Pattern[str] = re.compile(r"\d+")
_PROBED_SEGMENT_MARK: str = "<P>"

# The successful class of the positive control: 2xx.
_SUCCESS_MIN: int = 200
_SUCCESS_MAX: int = 299

# Label of the credential condition "no credential".
NO_CREDENTIAL: str = "none"


class Similarity(StrEnum):
    """
    How a response compares with the "does not exist here" reference.

    SAME_AS_UNKNOWN -- same fingerprint as a random sibling path: from this
                       answer alone, the path may not exist.
    DIFFERENT       -- a different fingerprint: the path is something else
                       than an unknown one.
    UNRELIABLE      -- the calibration of this pattern could not be trusted
                       (its probes differed, or were spoiled).
    """

    SAME_AS_UNKNOWN = "SAME_AS_UNKNOWN"
    DIFFERENT = "DIFFERENT"
    UNRELIABLE = "UNRELIABLE"


class Existence(StrEnum):
    """
    Whether the references prove that the judged endpoint exists.

    PROVEN      -- the positive control worked: a direct proof.
    INDICATED   -- the answer differs from what "does not exist here" looks
                   like: an indirect proof, resting on one assumption (the
                   random sibling, of the declared type, answers as a missing
                   object does).
    NOT_PROVEN  -- the answer is the same as an unknown sibling's, or the
                   positive control did not work, and nothing proves the
                   contrary.
    NOT_CHECKED -- no reference to decide (none asked, or the calibration was
                   not reliable).

    A test that counts a case as ENFORCED on INDICATED existence gives its
    finding-free verdict a lower confidence than on PROVEN (FIRM
    against CERTAIN).
    """

    PROVEN = "PROVEN"
    INDICATED = "INDICATED"
    NOT_PROVEN = "NOT_PROVEN"
    NOT_CHECKED = "NOT_CHECKED"


class ResponseFacts(BaseModel):
    """What a response is once the references are taken into account."""

    model_config = {"frozen": True}

    category: ResponseCategory = Field(description="The category the test judges.")
    existence: Existence = Field(description="Whether the endpoint is proven to exist.")
    non_standard_status: bool = Field(
        description="The status said something else than what the references prove."
    )


class Credential(BaseModel):
    """
    A credential condition of a reference request, given by the caller.

    The core does not know how the target expects a credential: the test
    helpers build the headers and query parameters (tests/helpers/auth.py,
    auth_parts) and give them here with a label naming the role (e.g. "user_a",
    "admin", "invalid").
    """

    model_config = {"frozen": True}

    label: str = Field(description="The role or condition, e.g. 'user_a', 'invalid'.")
    headers: dict[str, str] = Field(default_factory=dict, description="Headers to send.")
    params: dict[str, str] = Field(default_factory=dict, description="Query parameters to send.")


class Fingerprint(BaseModel):
    """What identifies the shape of an answer, regardless of the path asked."""

    model_config = {"frozen": True}

    status_code: int | None = Field(description="HTTP status; null without a response.")
    content_type: str = Field(description="Media type, lowercase, without parameters.")
    server: str = Field(description="The Server header, as sent.")
    body_shape: str = Field(description="The normalized body (see the module docstring).")


class CalibrationPoint(BaseModel):
    """What "does not exist here" looks like for one sibling pattern, method and credential."""

    model_config = {"frozen": True}

    pattern: str = Field(
        description=(
            "The sibling pattern: the path with `{*}` where a random value was put, e.g. "
            "`/api/v1/repos/{*}/{*}` (a template's parameters) or `/api/v1/{*}`."
        )
    )
    method: str = Field(description="The HTTP method of the probes (the judged request's).")
    credential: str = Field(description="The credential label (`none` without one).")
    reliable: bool = Field(description="Both probes got the same fingerprint, none was spoiled.")
    fingerprint: Fingerprint | None = Field(
        default=None, description="The common fingerprint, when reliable."
    )
    reason: str | None = Field(default=None, description="Why the point is not reliable.")
    record_ids: tuple[str, ...] = Field(description="The probes' records in evidence.json.")


class PositiveControl(BaseModel):
    """Whether a request works with a valid credential."""

    model_config = {"frozen": True}

    method: str = Field(description="HTTP method.")
    path: str = Field(description="The concrete path asked.")
    credential: str = Field(description="The credential label.")
    status_code: int | None = Field(description="HTTP status; null without a response.")
    works: bool = Field(description="The request was served (2xx).")
    record_id: str = Field(description="The record in evidence.json.")


def reference_ids(references: Sequence[CalibrationPoint | PositiveControl]) -> list[str]:
    """
    The record_ids of the references a verdict rests on, for Finding.supporting_refs.

    Args:
        references: Calibration points and positive controls.

    Returns:
        Their records' IDs, in order, without repetition.
    """
    ids: list[str] = []
    for reference in references:
        found = (
            reference.record_ids
            if isinstance(reference, CalibrationPoint)
            else (reference.record_id,)
        )
        ids.extend(rid for rid in found if rid not in ids)
    return ids


def fingerprint_of(record: EvidenceRecord, probed_segments: tuple[str, ...] = ()) -> Fingerprint:
    """
    The fingerprint of a recorded answer.

    Args:
        record:         The EvidenceRecord of the answer.
        probed_segments: The segments of the path asked in the pattern's
                         random positions, removed from a text body (servers
                         often repeat them in the error message).

    Returns:
        The Fingerprint.
    """
    headers = record.response_headers
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    return Fingerprint(
        status_code=record.response_status_code,
        content_type=content_type,
        server=headers.get("server", ""),
        body_shape=_body_shape(record.response_body or "", probed_segments),
    )


def _json_shape(value: object, depth: int) -> object:
    """The shape of a JSON value: the keys of objects down to depth, types below."""
    if isinstance(value, dict):
        if depth <= 0:
            return "object"
        return {key: _json_shape(item, depth - 1) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return "array"
    return type(value).__name__


def _body_shape(body: str, probed_segments: tuple[str, ...]) -> str:
    """The normalized body of a fingerprint."""
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None
    if isinstance(parsed, (dict, list)):
        return "json:" + json.dumps(_json_shape(parsed, _JSON_SHAPE_DEPTH), sort_keys=True)
    text = body
    for segment in sorted(probed_segments, key=len, reverse=True):
        if segment:
            text = text.replace(segment, _PROBED_SEGMENT_MARK)
    text = _UUID_PATTERN.sub("<U>", text)
    text = _HEX_PATTERN.sub("<H>", text)
    text = _NUMBER_PATTERN.sub("<N>", text)
    return "text:" + " ".join(text.split())[:_BODY_TEXT_CHARS]


def response_facts(
    record: EvidenceRecord,
    *,
    carried_credential: bool,
    similarity: Similarity | None = None,
    control: PositiveControl | None = None,
) -> ResponseFacts:
    """
    The category and the existence of a judged response, from its status and references.

    Existence, the first rule that holds: the positive control worked, PROVEN;
    the answer differs from an unknown sibling's, INDICATED; it is the same,
    NOT_PROVEN; the positive control did not work, NOT_PROVEN; otherwise
    NOT_CHECKED.

    Category: the status's (src/core/response_category.py), with one
    correction: NOT_FOUND when the positive control worked is a refusal under
    a misleading status (crAPI's dashboard answers 404 without a credential and
    200 with one): UNAUTHENTICATED when the judged request carried no
    credential, FORBIDDEN when it carried one; marked non-standard.

    Args:
        record:             The judged response.
        carried_credential: Whether the judged request carried a credential.
        similarity:         Its comparison with the calibration, if asked.
        control:            The positive control of the same request, if asked.

    Returns:
        The ResponseFacts.
    """
    category = categorize(record.response_status_code)
    works = control is not None and control.works
    if works:
        existence = Existence.PROVEN
    elif similarity == Similarity.DIFFERENT:
        existence = Existence.INDICATED
    elif similarity == Similarity.SAME_AS_UNKNOWN or control is not None:
        existence = Existence.NOT_PROVEN
    else:
        existence = Existence.NOT_CHECKED
    non_standard = category == ResponseCategory.NOT_FOUND and works
    if non_standard:
        category = (
            ResponseCategory.FORBIDDEN if carried_credential else ResponseCategory.UNAUTHENTICATED
        )
    return ResponseFacts(category=category, existence=existence, non_standard_status=non_standard)


# The random positions of a sibling pattern, by the kind of value they take:
# "{*}" a string, "{*integer}" an integer, "{*uuid}" a UUID.
RANDOM_SEGMENT: str = "{*}"
_KIND_INTEGER: str = "integer"
_KIND_UUID: str = "uuid"
_MARKER_PATTERN: re.Pattern[str] = re.compile(r"\{\*(integer|uuid)?\}")
_TEMPLATE_PARAMETER: re.Pattern[str] = re.compile(r"\{([^}/]+)\}")
_PATH_LOCATION: str = "path"
# Integer values: 13 digits, within int64, far from the small identifiers
# objects usually get.
_RANDOM_INTEGER_MIN: int = 10**12
_RANDOM_INTEGER_SPAN: int = 9 * 10**12
_INTEGER_TYPES: frozenset[str] = frozenset({"integer", "number"})


def _marker_for(parameter: ParameterInfo | None) -> str:
    """The random marker of a parameter, from its declared type and format."""
    if parameter is not None and parameter.schema_format == _KIND_UUID:
        return "{*" + _KIND_UUID + "}"
    if parameter is not None and parameter.schema_type in _INTEGER_TYPES:
        return "{*" + _KIND_INTEGER + "}"
    return RANDOM_SEGMENT


def random_token() -> str:
    """
    A random name no route or path is expected to hold.

    The neutral prefix and random hexadecimal characters the random siblings
    use, for a test that builds a path of its own and has to recognise its
    random part in an answer (fingerprint_of's probed_segments).

    Returns:
        The token, e.g. "zqxv3f9a1c".
    """
    return _PROBE_PREFIX + secrets.token_hex(_PROBE_RANDOM_BYTES)


def _random_value(kind: str | None) -> str:
    """A random value of a marker's kind (None or "" for a string)."""
    if kind == _KIND_INTEGER:
        return str(_RANDOM_INTEGER_MIN + secrets.randbelow(_RANDOM_INTEGER_SPAN))
    if kind == _KIND_UUID:
        return str(uuid.uuid4())
    return random_token()


def sibling_pattern(template_path: str, parameters: Sequence[ParameterInfo] = ()) -> str:
    """
    The pattern of the random siblings of a path.

    A path with parameters keeps its template, with a random marker in place of
    every parameter, of the kind its declaration says (an integer, a UUID,
    otherwise a string), and the text around it in the segment: its siblings
    are objects that do not exist, on the same route. A path without
    parameters gets RANDOM_SEGMENT in place of its last segment.

    Args:
        template_path: The path as the specification writes it, e.g.
                       "/api/v1/repos/{owner}/{repo}" or "/api/v1/user".
        parameters:    The operation's parameters (EndpointRecord.parameters);
                       a path parameter not declared counts as a string.

    Returns:
        e.g. "/api/v1/repos/{*}/{*}", "/shop/orders/{*integer}", "/api/v1/{*}".
    """
    declared = {p.name: p for p in parameters if p.location == _PATH_LOCATION}
    if _TEMPLATE_PARAMETER.search(template_path):
        return _TEMPLATE_PARAMETER.sub(
            lambda m: _marker_for(declared.get(m.group(1))), template_path
        )
    segments = [segment for segment in template_path.split("/") if segment]
    return "/" + "/".join([*segments[:-1], RANDOM_SEGMENT])


def random_sibling_path(template_path: str, parameters: Sequence[ParameterInfo] = ()) -> str:
    """
    A concrete path addressing objects that do not exist, from a template.

    The sibling pattern of the path (sibling_pattern) with a random value of
    each parameter's declared type in it: a test probing a template without
    touching any real object asks this path, and its calibration asks paths of
    the same shape.

    Args:
        template_path: The path as the specification writes it.
        parameters:    The operation's parameters (EndpointRecord.parameters).

    Returns:
        e.g. "/api/v1/repos/zqxv4f2a/zqxv91bd" for
        "/api/v1/repos/{owner}/{repo}".
    """
    path, _values = _fill_pattern(sibling_pattern(template_path, parameters))
    return path


def _fill_pattern(pattern: str) -> tuple[str, tuple[str, ...]]:
    """A concrete path from a pattern: (path, the random values put in it)."""
    values: list[str] = []

    def fill(match: re.Match[str]) -> str:
        value = _random_value(match.group(1))
        values.append(value)
        return value

    return _MARKER_PATTERN.sub(fill, pattern), tuple(values)


def _random_positions(pattern: str, path: str) -> tuple[str, ...]:
    """The values of a concrete path at the pattern's random positions."""
    regex = ""
    last = 0
    for marker in _MARKER_PATTERN.finditer(pattern):
        regex += re.escape(pattern[last : marker.start()]) + "([^/]+)"
        last = marker.end()
    regex += re.escape(pattern[last:])
    match = re.fullmatch(regex, path.split("?", 1)[0])
    if match is None:
        segments = [segment for segment in path.split("/") if segment]
        return tuple(segments[-1:])
    return match.groups()


class ReferenceResponses:
    """
    The reference responses of one run (calibration points, positive controls).

    One instance per run, created by the engine with the run's client and
    evidence store and reached through TestContext.references. Not thread-safe:
    the tests run one after another.
    """

    def __init__(self, client: SecurityClient, store: EvidenceStore) -> None:
        """
        Start an empty set of references.

        Args:
            client: The run's SecurityClient (the reference requests go through it).
            store:  The run's EvidenceStore (each reference record is pinned).
        """
        self._client = client
        self._store = store
        self._points: dict[tuple[str, str, str], CalibrationPoint] = {}
        self._controls: dict[tuple[str, str, str], PositiveControl] = {}
        self._refusal: CalibrationPoint | None = None

    # ------------------------------------------------------------------
    # Calibration
    # ------------------------------------------------------------------

    def same_as_unknown(
        self,
        record: EvidenceRecord,
        template_path: str,
        credential: Credential | None = None,
        parameters: Sequence[ParameterInfo] = (),
    ) -> Similarity:
        """
        Compare a response with what "does not exist here" looks like.

        Args:
            record:        The judged response, asked with the same credential
                           condition as `credential` (none when None).
            template_path: Its path as the specification writes it; the pattern
                           of its siblings comes from it (sibling_pattern).
            credential:    The credential the judged request carried, if any.
            parameters:    The operation's parameters, for the type of the random
                           values (EndpointRecord.parameters).

        Returns:
            SAME_AS_UNKNOWN, DIFFERENT, or UNRELIABLE (the judged response or the
            calibration cannot be trusted).
        """
        if categorize(record.response_status_code) in _SPOILING_CATEGORIES:
            return Similarity.UNRELIABLE
        pattern = sibling_pattern(template_path, parameters)
        point = self.calibration(pattern, record.request_method, credential)
        if not point.reliable or point.fingerprint is None:
            return Similarity.UNRELIABLE
        path = "/" + record.request_url.split("://", 1)[-1].split("/", 1)[-1]
        same = fingerprint_of(record, _random_positions(pattern, path)) == point.fingerprint
        return Similarity.SAME_AS_UNKNOWN if same else Similarity.DIFFERENT

    def calibration(
        self, pattern: str, method: str = "GET", credential: Credential | None = None
    ) -> CalibrationPoint:
        """
        The calibration point of a sibling pattern, method and credential, probed on first use.

        Args:
            pattern:    The sibling pattern (sibling_pattern), with its random
                        markers ("{*}", "{*integer}", "{*uuid}").
            method:     The HTTP method of the probes.
            credential: The credential condition of the probes (None: none).

        Returns:
            The CalibrationPoint (from the cache after the first call).
        """
        label = credential.label if credential is not None else NO_CREDENTIAL
        key = (pattern, method.upper(), label)
        cached = self._points.get(key)
        if cached is not None:
            return cached
        point = self._probe_point(pattern, method.upper(), credential, label)
        self._points[key] = point
        log.info(
            "reference_calibration_point",
            pattern=pattern,
            method=method.upper(),
            credential=label,
            reliable=point.reliable,
            reason=point.reason,
            status_code=point.fingerprint.status_code if point.fingerprint else None,
        )
        return point

    def _probe_point(
        self, pattern: str, method: str, credential: Credential | None, label: str
    ) -> CalibrationPoint:
        """Send the random sibling probes of one point and build it."""
        fingerprints: list[Fingerprint] = []
        record_ids: list[str] = []
        reason: str | None = None
        for _ in range(_PROBES_PER_POINT):
            path, names = _fill_pattern(pattern)
            record = self._send(method, path, credential)
            record_ids.append(record.record_id)
            category = categorize(record.response_status_code)
            if category in _SPOILING_CATEGORIES:
                reason = f"a probe got {category.value}: the answer says nothing about the path"
                break
            fingerprints.append(fingerprint_of(record, names))
        if reason is None and len(set(fingerprints)) != 1:
            reason = "the two random probes got different answers"
        reliable = reason is None
        return CalibrationPoint(
            pattern=pattern,
            method=method,
            credential=label,
            reliable=reliable,
            fingerprint=fingerprints[0] if reliable else None,
            reason=reason,
            record_ids=tuple(record_ids),
        )

    # ------------------------------------------------------------------
    # Gateway refusal
    # ------------------------------------------------------------------

    def gateway_refusal(self) -> CalibrationPoint:
        """
        What the gateway answers when none of its routes matches, probed on first use.

        Two unauthenticated GET requests to random paths at the root, which no
        route and no specification path is expected to match. The point is
        reliable when both got the same answer; a caller compares a response
        with it by fingerprint_of(record, its own random segments) ==
        point.fingerprint.

        Unlike calibration(), an answer that refuses the request does not spoil
        the probe: a refusal is what is being measured, so a gateway that
        answers 401 or 403 to an unrouted path has that as its refusal. The
        point is unreliable only when the two probes answered differently.

        Returns:
            The CalibrationPoint of the refusal (from the cache after the first
            call), its pattern being the root pattern "/{*}".
        """
        if self._refusal is not None:
            return self._refusal
        fingerprints: list[Fingerprint] = []
        record_ids: list[str] = []
        for _ in range(_PROBES_PER_POINT):
            path, names = _fill_pattern(_ROOT_PATTERN)
            record = self._send("GET", path, None)
            record_ids.append(record.record_id)
            fingerprints.append(fingerprint_of(record, names))
        differed = len(set(fingerprints)) != 1
        reason = "the two random paths got different answers" if differed else None
        reliable = reason is None
        point = CalibrationPoint(
            pattern=_ROOT_PATTERN,
            method="GET",
            credential=NO_CREDENTIAL,
            reliable=reliable,
            fingerprint=fingerprints[0] if reliable else None,
            reason=reason,
            record_ids=tuple(record_ids),
        )
        self._refusal = point
        log.info(
            "reference_gateway_refusal",
            reliable=point.reliable,
            reason=point.reason,
            status_code=point.fingerprint.status_code if point.fingerprint else None,
        )
        return point

    # ------------------------------------------------------------------
    # Positive control
    # ------------------------------------------------------------------

    def positive_control(self, method: str, path: str, credential: Credential) -> PositiveControl:
        """
        Whether a request works with a valid credential, asked once.

        The caller chooses the credential (the role whose access the endpoint
        is meant for) and the method; a request with side effects is the
        caller's responsibility (the effect the test declares).

        Args:
            method:     HTTP method.
            path:       The concrete path (parameters already resolved).
            credential: The valid credential to send.

        Returns:
            The PositiveControl (from the cache after the first call).
        """
        key = (method.upper(), path, credential.label)
        cached = self._controls.get(key)
        if cached is not None:
            return cached
        record = self._send(method, path, credential)
        status = record.response_status_code
        control = PositiveControl(
            method=method.upper(),
            path=path,
            credential=credential.label,
            status_code=status,
            works=status is not None and _SUCCESS_MIN <= status <= _SUCCESS_MAX,
            record_id=record.record_id,
        )
        self._controls[key] = control
        log.info(
            "reference_positive_control",
            method=control.method,
            path=path,
            credential=credential.label,
            status_code=status,
            works=control.works,
        )
        return control

    # ------------------------------------------------------------------
    # Requests and summary
    # ------------------------------------------------------------------

    def _send(self, method: str, path: str, credential: Credential | None) -> EvidenceRecord:
        """Send one reference request and pin its record (a response or none)."""
        try:
            _, record = self._client.request(
                method,
                path,
                test_id=REFERENCE_TEST_ID,
                headers=dict(credential.headers) if credential else None,
                params=dict(credential.params) if credential and credential.params else None,
            )
        except SecurityClientError as exc:
            if exc.record is None:
                raise
            record = exc.record
        self._store.pin_evidence(record)
        return record

    def summary(self) -> tuple[list[CalibrationPoint], list[PositiveControl]]:
        """
        Every reference of the run, for the report.

        Returns:
            (calibration points, positive controls), in the order they were
            made; the gateway refusal, when it was measured, is the last
            calibration point.
        """
        points = list(self._points.values())
        if self._refusal is not None:
            points.append(self._refusal)
        return points, list(self._controls.values())
