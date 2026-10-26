"""
src/external_tests/ext_test_0_1_undocumented_paths_ffuf.py

ExtTest01UndocumentedPathsFfuf: guarantee 0.1, "every exposed endpoint is
documented", the path search.

ffuf proposes, the test proves. ffuf searches for paths under the base paths
derived from the specification; every path it reports that the specification
does not document is requested again by the test with the tool's client and
judged against the calibration (src/core/references.py): it exists when it
answers unlike random siblings under the same parent. The verdict and its proof
rest only on the tool's own requests (ffuf does not verify TLS certificates and
is given no credentials, src/connectors/ffuf.py).

Base paths (one ffuf run each): the root; the service prefixes derived in Phase 2
(service_prefixes, e.g. /identity/api); the version directories of the
documented paths (/identity/api/v2, /api/v1). Words: SecLists
common-api-endpoints-mazen160.txt and the sensitive-path catalogue
(src/core/sensitive_paths.py) under every base path; the whole paths of SecLists
api/api-endpoints.txt each under the longest base path it starts with (from the
root otherwise), so that every ffuf run stays inside one service and its
calibration holds (on Forgejo, api/v1/... tried from the root reach Forgejo
through the gateway's /api route while ffuf calibrated on the gateway's own 404:
212 answers kept); and the user's list (wordlist) under every base path.

Before trusting the search, each base path is calibrated: what an unknown path
answers there. A base path that refuses an unknown path (401, 403) instead of
reporting it missing hides its paths from an unauthenticated search, and is
recorded NOT_VERIFIABLE (crAPI's identity service, 2026-10-21: every path
answers 401, so ffuf kept nothing and a PASS would have claimed more than was
verified).

Not judged (listed in a note): a path that matches a documented template
(/repos/a/b for /repos/{owner}/{repo}), a parent of documented paths (/api), the
specification's own URL.

Oracle (sub-test undocumented_paths):

    answers unlike its unknown siblings          VIOLATION/UNDOCUMENTED_PATH  FIRM
    answers "not found" (404, 410) of another     NOT_APPLICABLE/NOT_FOUND (another component
      shape                                       said "not found": e.g. Kong's route /api also
                                                  matches /api-docs, which Forgejo answers 404)
    answers like an unknown sibling               NOT_APPLICABLE/LIKE_UNKNOWN (a false
                                                  positive of the tool)
    the base path refuses an unknown path          NOT_VERIFIABLE/SEARCH_BLIND (401, 403: an
      instead of reporting it missing              unauthenticated search cannot tell an
                                                  existing path from a missing one there)
    calibration unstable                          NOT_VERIFIABLE/CALIBRATION_UNSTABLE
    unavailable, rate limited, no response        NOT_VERIFIABLE/<category>
    ffuf kept more than MAX_CANDIDATES_PER_BASE   NOT_VERIFIABLE/TOOL_CALIBRATION_FAILED
      answers on one base path                    (its own calibration did not hold)
    the search ended with no violation            ENFORCED/NO_UNDOCUMENTED_PATH

Only this question: whether the path requires a credential (1.1), shows
credentials (6.4) or is forwarded by a gateway without a route (0.2) is judged
by those tests.

Dependency rule:
    Imports from: stdlib, structlog, pydantic, src.connectors, src.core,
                  src.external_tests.base.
    Must never import from: tests/, config/, discovery/, report/, engine.py.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.connectors.base import BaseConnector, ConnectorResult
from src.connectors.ffuf import FfufConnector, FfufJob
from src.core.context import TargetContext
from src.core.exceptions import ExternalToolError, SecurityClientError
from src.core.models import (
    Confidence,
    EndpointRecord,
    Finding,
    InfoNote,
    Outcome,
    Reference,
    ResponseCategory,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.references import RANDOM_SEGMENT, Similarity, sibling_pattern
from src.core.response_category import categorize
from src.core.sensitive_paths import SENSITIVE_PATHS
from src.core.test_metadata import Effect, TestInfo
from src.external_tests.base import ExternalToolTest, ToolRun

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The SecLists lists, under external_tools.ffuf.wordlist_dir (install_tools.sh).
_WORDS_UNDER_BASE: str = "Discovery/Web-Content/common-api-endpoints-mazen160.txt"
_PATHS_FROM_ROOT: str = "Discovery/Web-Content/api/api-endpoints.txt"
# The file install_tools.sh writes with the SecLists release, for the report.
_WORDLIST_VERSION_FILE: str = "VERSION"
_COMMENT_PREFIX: str = "#"

# The derivation rules whose facts give base paths (src/discovery/derivation.py).
_RULE_SERVICE_PREFIXES: str = "service_prefixes"

# A path segment shaped as an API version (the same shape as the derivation rule).
_VERSION_SEGMENT: re.Pattern[str] = re.compile(r"^v\d+(\.\d+)*$", re.IGNORECASE)
_TEMPLATE_PARAMETER: re.Pattern[str] = re.compile(r"\{[^}/]+\}")

# More answers than this kept by ffuf on one base path means its calibration did
# not hold there (a target answering every path differently): re-verifying them
# would cost one request each and say nothing; the base path is not verifiable.
MAX_CANDIDATES_PER_BASE: int = 100

# How many paths a note lists by name.
_NOTE_EXAMPLES: int = 10

# The categories in which a base path refuses an unknown path instead of
# reporting it missing: an unauthenticated search is blind there.
_REFUSING: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.UNAUTHENTICATED, ResponseCategory.FORBIDDEN}
)

_SUB_TEST: str = "undocumented_paths"
_SPOILING_DETAIL: dict[ResponseCategory, str] = {
    ResponseCategory.UPSTREAM_UNAVAILABLE: "UPSTREAM_UNAVAILABLE",
    ResponseCategory.RATE_LIMITED: "RATE_LIMITED",
    ResponseCategory.NO_RESPONSE: "NO_RESPONSE",
}

_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API9:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-13.4.5"),
    Reference(standard=Standard.WSTG, id="WSTG-v42-CONF-04"),
    Reference(standard=Standard.WSTG, id="WSTG-v42-CONF-05"),
)


class ExtTest01FfufParams(BaseModel):
    """Parameters of ext.0.1.ffuf (tests.domain_0.ext_0_1_ffuf)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    wordlist: str | None = Field(
        default=None,
        description=(
            "A list of the user's (one word or path per line), tried under every base path "
            "besides the default lists, e.g. Assetnote's `httparchive_apiroutes` for a deep "
            "search (364,056 paths: at 30 requests per second about 3.4 hours per base path). "
            "Relative to the working directory."
        ),
    )

    @field_validator("wordlist")
    @classmethod
    def _readable(cls, value: str | None) -> str | None:
        """Reject a list that is not a readable file, when the configuration is loaded."""
        if value is not None and not Path(value).is_file():
            raise ValueError(f"wordlist {value!r} is not a file")
        return value


def _read_list(path: Path) -> list[str]:
    """The entries of a wordlist: one per line, blank lines and comments left out."""
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.startswith(_COMMENT_PREFIX)
    ]


def _unique(items: list[str]) -> tuple[str, ...]:
    """The items without repetitions, in their first order."""
    return tuple(dict.fromkeys(items))


def _base_paths(target: TargetContext) -> list[str]:
    """
    The base paths of the search, each ending with "/".

    The root, the derived service prefixes and the version directories of the
    documented paths (the path up to and including a version segment).
    """
    surface = target.attack_surface
    bases = ["/"]
    if surface is None:
        return bases
    for fact in surface.derived_facts(_RULE_SERVICE_PREFIXES):
        bases.append(fact.value.rstrip("/") + "/")
    for endpoint in surface.endpoints:
        segments = endpoint.path.split("/")
        for position, segment in enumerate(segments):
            if _VERSION_SEGMENT.match(segment):
                bases.append("/".join(segments[: position + 1]) + "/")
    return list(_unique(bases))


def _template_regex(template: str) -> re.Pattern[str]:
    """A documented path as a regular expression: a parameter matches one segment."""
    parts = _TEMPLATE_PARAMETER.split(template)
    return re.compile("[^/]+".join(re.escape(part) for part in parts) + "/?")


class ExtTest01UndocumentedPathsFfuf(ExternalToolTest[ExtTest01FfufParams]):
    """
    ext.0.1.ffuf: undocumented paths answer (path search with ffuf, re-verified).

    The oracle, the base paths and the words are in the module docstring.
    """

    info = TestInfo(
        id="ext.0.1.ffuf",
        name="Undocumented Paths Answer (ffuf path search, re-verified)",
        priority=0,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-912",
        references=_REFERENCES,
        tags=("inventory", "shadow-api"),
        tool="ffuf",
        effect=Effect.STRESSES_TARGET,
        sub_tests=(_SUB_TEST,),
    )

    def _build_connector(self) -> BaseConnector:
        """The ffuf connector (no I/O)."""
        return FfufConnector()

    def _invoke_connector(
        self,
        connector: BaseConnector,
        target: TargetContext,
        target_url: str,
    ) -> ConnectorResult:
        """
        Build one ffuf job per base path and run them.

        Args:
            connector:  The FfufConnector, confirmed available.
            target:     The run's TargetContext (surface, configuration).
            target_url: The target's base URL.

        Returns:
            ConnectorResult: every answer ffuf kept, with its base URL.

        Raises:
            ExternalToolError: The pinned lists are missing (install_tools.sh not
                               run) or ffuf failed.
        """
        if not isinstance(connector, FfufConnector):
            raise TypeError(f"expected FfufConnector, got {type(connector).__name__}")
        cfg = target.external_tools.ffuf
        lists_dir = Path(cfg.wordlist_dir)
        under_base_file = lists_dir / _WORDS_UNDER_BASE
        from_root_file = lists_dir / _PATHS_FROM_ROOT
        missing = [str(p) for p in (under_base_file, from_root_file) if not p.is_file()]
        if missing:
            raise ExternalToolError(
                message=(
                    f"ffuf wordlists not found: {', '.join(missing)}. Run install_tools.sh, or "
                    "set external_tools.ffuf.wordlist_dir to the SecLists directory."
                ),
                tool_name=connector.TOOL_NAME,
                exit_code=-1,
            )
        words = _read_list(under_base_file) + [p.suffix for p in SENSITIVE_PATHS]
        user_list = self.params(target).wordlist
        if user_list is not None:
            words += _read_list(Path(user_list))
        bases = _base_paths(target)
        extra: dict[str, list[str]] = {base: [] for base in bases}
        for entry in _read_list(from_root_file):
            full = "/" + entry.lstrip("/")
            base = max((b for b in bases if full.startswith(b)), key=len)
            extra[base].append(full[len(base) :])
        jobs = [
            FfufJob(base_url=target_url + base, words=_unique(words + extra[base]))
            for base in bases
        ]
        log.info(
            "ext_test_0_1_ffuf_jobs",
            base_paths=[job.base_url for job in jobs],
            requests=sum(len(job.words) for job in jobs),
        )
        return connector.run(
            jobs=jobs,
            timeout_seconds=cfg.timeout_seconds or 0,
            per_request_timeout=cfg.per_request_timeout,
            rate_limit_rps=cfg.rate_limit_rps,
        )

    def _evaluate(self, result: ConnectorResult, run: ToolRun) -> TestResult:
        """
        Re-verify every undocumented path ffuf reported and judge it (module docstring).

        Args:
            result: The ffuf answers, each with its base URL.
            run:    The run (target, context with the references, client, store).

        Returns:
            TestResult: self._finish().
        """
        target = run.target
        surface = target.attack_surface
        endpoints: list[EndpointRecord] = surface.endpoints if surface is not None else []
        documented = sorted({endpoint.path for endpoint in endpoints})
        templates = [_template_regex(path) for path in documented]
        spec_path = urlsplit(str(target.openapi_spec_url)).path if target.openapi_spec_url else None

        by_base: dict[str, list[str]] = {}
        for item in result.raw_output.get("results", []):
            path = urlsplit(str(item.get("url", ""))).path or "/"
            by_base.setdefault(str(item.get("base_url", "")), []).append(path)

        not_judged: list[str] = []
        candidates: list[str] = []
        for base, paths in by_base.items():
            if len(paths) > MAX_CANDIDATES_PER_BASE:
                self._record(_SUB_TEST, Outcome.NOT_VERIFIABLE, "TOOL_CALIBRATION_FAILED")
                not_judged.append(f"{base}: {len(paths)} answers kept by ffuf, not re-verified")
                continue
            for path in paths:
                bare = path.rstrip("/") or "/"
                if (
                    any(t.fullmatch(path) for t in templates)
                    or any(doc.startswith(bare + "/") for doc in documented)
                    or path == spec_path
                ):
                    not_judged.append(path)
                elif bare not in candidates:
                    candidates.append(bare)

        verifiable = self._searchable_bases(result, run)
        violations = 0
        for path in candidates:
            violations += self._verify(path, run)
        if violations == 0 and verifiable:
            # Claimed only where the search could tell an existing path from a
            # missing one; with no such base path the sub-test is INCONCLUSIVE.
            self._record(_SUB_TEST, Outcome.ENFORCED, "NO_UNDOCUMENTED_PATH")

        notes: list[InfoNote] = []
        if not_judged:
            shown = ", ".join(not_judged[:_NOTE_EXAMPLES])
            more = len(not_judged) - _NOTE_EXAMPLES
            notes.append(
                InfoNote(
                    title=f"{len(not_judged)} answer(s) of ffuf not judged",
                    detail=(
                        "Documented paths, parents of documented paths, the specification's own "
                        f"URL, or base paths where ffuf's calibration did not hold: {shown}"
                        + (f" and {more} more" if more > 0 else "")
                        + f" (raw output '{run.artifact_ref}')."
                    ),
                )
            )
        notes.append(self._lists_note(target, result))
        return self._finish(
            notes=notes,
            message=(
                f"ffuf searched {len(result.raw_output.get('base_urls', []))} base path(s) and "
                f"kept {result.raw_output.get('all_count', 0)} answer(s); "
                f"{len(candidates)} undocumented candidate(s) re-verified."
            ),
        )

    def _searchable_bases(self, result: ConnectorResult, run: ToolRun) -> int:
        """
        Calibrate every base path searched and count those where a search can tell.

        A base path that refuses an unknown path (401, 403) instead of
        reporting it missing hides its paths from an unauthenticated search:
        it is recorded NOT_VERIFIABLE, so that the result says what was not
        verified instead of claiming a clean search.

        Args:
            result: The connector's output (its base_urls).
            run:    The run (the references).

        Returns:
            How many base paths a search can tell something about.
        """
        verifiable = 0
        for base_url in result.raw_output.get("base_urls", []):
            base = urlsplit(str(base_url)).path or "/"
            point = run.context.references.calibration(base + RANDOM_SEGMENT)
            if not point.reliable or point.fingerprint is None:
                self._record(_SUB_TEST, Outcome.NOT_VERIFIABLE, "CALIBRATION_UNSTABLE")
                continue
            if categorize(point.fingerprint.status_code) in _REFUSING:
                self._record(_SUB_TEST, Outcome.NOT_VERIFIABLE, "SEARCH_BLIND")
                continue
            verifiable += 1
        return verifiable

    def _verify(self, path: str, run: ToolRun) -> int:
        """
        Request one undocumented candidate again and judge it against the calibration.

        Args:
            path: The candidate's path (no trailing slash).
            run:  The run.

        Returns:
            1 when the path is judged a violation, 0 otherwise.
        """
        try:
            _response, record = run.client.request("GET", path, test_id=self.info.id)
        except SecurityClientError as exc:
            if exc.record is None:
                raise
            self._judge(exc.record, run.store, _SUB_TEST, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return 0
        references = run.context.references
        similarity = references.same_as_unknown(record, template_path=path)
        point = references.calibration(sibling_pattern(path))
        category = categorize(record.response_status_code)
        if similarity == Similarity.UNRELIABLE:
            detail = _SPOILING_DETAIL.get(category, "CALIBRATION_UNSTABLE")
            self._judge(record, run.store, _SUB_TEST, Outcome.NOT_VERIFIABLE, detail)
            return 0
        if similarity == Similarity.SAME_AS_UNKNOWN:
            self._judge(record, run.store, _SUB_TEST, Outcome.NOT_APPLICABLE, "LIKE_UNKNOWN")
            return 0
        if category == ResponseCategory.NOT_FOUND:
            # A "not found" never proves a path exists, whatever its shape: another
            # component answered it (a gateway's prefix route forwarding it).
            self._judge(record, run.store, _SUB_TEST, Outcome.NOT_APPLICABLE, "NOT_FOUND")
            return 0
        self._judge(
            record,
            run.store,
            _SUB_TEST,
            Outcome.VIOLATION,
            "UNDOCUMENTED_PATH",
            finding=Finding(
                title=f"Undocumented path answers: GET {path}",
                detail=(
                    f"GET {path} (no credential) answered {record.response_status_code} "
                    f"({category.value}), unlike random paths under the same parent (calibration "
                    f"{point.pattern}); the specification documents no operation on this path. "
                    "Document it or remove it; whether it requires a credential or exposes data "
                    "is judged by tests 1.1 and 6.4."
                ),
                confidence=Confidence.FIRM,
            ),
            reference_responses=(point,),
        )
        return 1

    def _lists_note(self, target: TargetContext, result: ConnectorResult) -> InfoNote:
        """The note of what the search used: ffuf's version, the lists and their release."""
        cfg = target.external_tools.ffuf
        version_file = Path(cfg.wordlist_dir) / _WORDLIST_VERSION_FILE
        release = (
            version_file.read_text(encoding="utf-8").strip() if version_file.is_file() else "?"
        )
        user_list = self.params(target).wordlist
        return InfoNote(
            title="What the path search used",
            detail=(
                f"{result.tool_version or 'ffuf'}; SecLists {release}: {_WORDS_UNDER_BASE} and "
                f"the {len(SENSITIVE_PATHS)} sensitive paths of the tool under every base path, "
                f"{_PATHS_FROM_ROOT} from the root"
                + (f"; the user's list {user_list}" if user_list else "")
                + f"; {cfg.rate_limit_rps} requests per second, unauthenticated GET only."
            ),
        )
