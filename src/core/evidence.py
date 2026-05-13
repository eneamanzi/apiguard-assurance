"""
src/core/evidence.py

EvidenceStore: streaming per-test evidence recorder with unbounded capacity.

Architecture (v2.0 — streaming JSONL):
    The previous implementation used a bounded in-memory deque (maxlen=100).
    That design had a structural flaw: high-volume tests such as Test 1.1
    (authentication enforcement across all protected endpoints) can produce
    tens or hundreds of FAIL evidence records in a single execution.  When
    the buffer filled, Python's deque silently evicted the oldest records
    via round-robin, causing FAIL evidence from early P0 tests to disappear
    from evidence.json.  The Finding.evidence_ref field pointed to a
    record_id that no longer existed -- a broken audit trail.

    v2.0 replaces the in-memory deque with a streaming write model:

        Phase 3 (bootstrap):
            EvidenceStore is constructed with the path to a temporary
            directory (outputs/evidence_tmp/).  The directory is created
            immediately.  No files are written yet.

        Phase 5 (execution -- per test):
            Before each test executes, the engine calls
            store.begin_test(test_id).  This opens a per-test JSONL file:
                outputs/evidence_tmp/<test_id_safe>.jsonl
            The file handle remains open for the duration of the test.
            add_fail_evidence() and pin_evidence() write one JSON line
            per record immediately and flush to disk -- O(1) memory,
            unbounded capacity.  After the test completes, the engine
            calls store.end_test() which closes the file handle.

        Phase 7 (report generation):
            The engine calls store.merge_and_finalize(output_path).
            This method:
              1. Reads all *.jsonl files from the tmp directory.
              2. Deserializes each line back into an EvidenceRecord.
              3. Sorts all records chronologically by timestamp_utc.
              4. Writes the final evidence.json in the same envelope
                 format as v1.0 (fully backward-compatible).
              5. Removes the evidence_tmp/ directory and all its contents.

    Crash resilience:
        If the process is killed between Phase 5 and Phase 7, the
        evidence_tmp/ directory remains on disk with all per-test JSONL
        files intact and human-readable.  Re-running the tool will
        recreate the directory (exist_ok=True) and overwrite stale files.

    Tool artifact disk persistence (v2.1 addition):
        When initialized with a tools_dir, pin_artifact() writes a
        standalone JSON copy of each external tool's sanitized raw output
        to outputs/tools/<label>.json.  This enables direct inspection
        of tool output (e.g., testssl.sh JSON) without parsing evidence.json.
        Write failures are non-blocking: logged as WARNING, never propagated.

    Backward-compatible public interface for tests (unchanged from v1.0):
        add_fail_evidence(record)  -- unchanged
        pin_evidence(record)       -- unchanged
        record_count               -- now reflects total records on disk
        is_empty                   -- unchanged
        get_by_id(record_id)       -- scans current test's in-memory buffer
        iter_records()             -- iterates current test's in-memory buffer

    New Phase-lifecycle methods (called exclusively by engine.py):
        begin_test(test_id)        -- opens per-test JSONL file
        end_test()                 -- flushes and closes current JSONL file
        merge_and_finalize(path)   -- merges all JSONL -> evidence.json,
                                      removes tmp dir

    Thread safety:
        Not thread-safe by design.  Sequential execution guaranteed by the
        tool architecture (Implementazione.md, Section 4.3).
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

import structlog

from src.core.models import EvidenceRecord

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum length of response_body stored per record, in characters.
# The actual truncation is enforced by EvidenceRecord's field_validator
# in models.py.  This constant is kept here as a documentation anchor.
RESPONSE_BODY_MAX_CHARS: int = 10_000

# Default output filename for the merged evidence archive produced in Phase 7.
EVIDENCE_OUTPUT_FILENAME: str = "evidence.json"

# Extension for per-test streaming files inside evidence_tmp/.
_JSONL_EXTENSION: str = ".jsonl"

# Characters in test_id that are invalid or problematic in filenames.
# The dot in "1.1" would be misread as an extension; slashes would create
# subdirectories.  Both are replaced with underscores for filesystem safety.
_TEST_ID_UNSAFE_CHARS: str = "./"

# ---------------------------------------------------------------------------
# Sanitization constants -- used by EvidenceStore._sanitize_artifact()
# Defined at module level to satisfy Ruff N806 (no UPPER_CASE in functions).
# ---------------------------------------------------------------------------

# Key name fragments that indicate a credential-bearing value (case-insensitive
# substring match against the lowercased key).  Any dict value whose key
# contains one of these substrings is unconditionally replaced with
# "[REDACTED]" regardless of its content.
_SANITIZE_SENSITIVE_KEY_PATTERNS: tuple[str, ...] = (
    "token",
    "password",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "secret",
    "credential",
    "auth",
)

# Word-boundary regex compiled from _SANITIZE_SENSITIVE_KEY_PATTERNS.
#
# Purpose: prevents bare-substring false positives such as "author" → redacted
# because "auth" is a substring of "author".  The negative lookbehind
# (?<![a-z]) and lookahead (?![a-z]) enforce that each pattern is surrounded
# by non-letter characters (separators: -, _, ., space, start/end of string).
#
# Concrete examples:
#   "author"          -> "auth" followed by "o" (letter) -> NOT matched  ✓
#   "auth_token"      -> "auth" followed by "_" (non-letter) -> matched  ✓
#   "x-auth-token"    -> "auth" preceded/followed by "-" -> matched      ✓
#   "authorization"   -> "authorization" as a whole word -> matched       ✓
#   "oauth_token"     -> "auth" preceded by "o" (letter) -> NOT matched;
#                        "token" matched via own pattern                  ✓
#
# The pattern is case-insensitive via re.IGNORECASE even though
# _redact_value() lowercases keys first; the flag adds safety in case the
# function is called with a non-lowercased key in future refactors.
_SENSITIVE_KEY_RE: re.Pattern[str] = re.compile(
    r"(?<![a-z])(?:"
    + "|".join(re.escape(p) for p in _SANITIZE_SENSITIVE_KEY_PATTERNS)
    + r")(?![a-z])",
    re.IGNORECASE,
)

# JWT heuristic: three base64url segments separated by dots, no whitespace.
# Applied to string values whose key does NOT match a sensitive pattern but
# whose content looks like a JWT (structural leak via value, not key naming).
_SANITIZE_JWT_PATTERN: re.Pattern[str] = re.compile(
    r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
)

# HTTP Authorization header value prefixes that indicate a credential in the
# string content itself (e.g., a captured Authorization header value stored
# in an arbitrary dict field whose key name was not caught above).
#
# Case-sensitive note: Python str.startswith() is case-sensitive.
# "Token " (title-case) covers the RFC 6750 non-standard variant used by some
# API clients. "token " (lowercase) covers the Forgejo/Gitea native format
# produced by _bearer_headers() in tests/helpers/forgejo_resources.py.
# Both must be present to guarantee redaction of Forgejo tokens in artifacts.
_SANITIZE_HEADER_PREFIXES: tuple[str, ...] = ("Bearer ", "Basic ", "Token ", "token ")

# Characters unsafe for use in filenames produced by _persist_tool_artifact().
# Dots create ambiguous extensions; slashes create subdirectories; spaces are
# problematic on some shells.  All replaced with underscores.
_ARTIFACT_FILENAME_UNSAFE_CHARS: str = "./\\ "


# ---------------------------------------------------------------------------
# EvidenceStore
# ---------------------------------------------------------------------------


class EvidenceStore:
    """
    Streaming per-test evidence recorder with unbounded on-disk capacity.

    Replaces the v1.0 bounded deque (maxlen=100) that caused silent eviction
    of FAIL evidence records on high-volume tests such as Test 1.1.

    The store is lifecycle-aware: it must be driven by three phase calls from
    engine.py in the correct order:

        store.begin_test(test_id)   # before each test.execute()
        store.end_test()            # after each test.execute()
        store.merge_and_finalize()  # once, at the start of Phase 7

    Tests themselves only call add_fail_evidence() and pin_evidence(), which
    are unchanged from v1.0.  Tests have zero awareness of the file-based
    storage mechanism.

    Usage pattern inside engine.py Phase 5:

        for test in batch:
            store.begin_test(test.test_id)
            result = test.execute(target, context, client, store)
            store.end_test()
            result_set.add_result(result)

    Usage pattern inside a BaseTest.execute() implementation (UNCHANGED):

        store.add_fail_evidence(record)  # FAIL transaction
        store.pin_evidence(record)       # key setup transaction
    """

    def __init__(self, tmp_dir: Path, tools_dir: Path | None = None) -> None:
        """
        Initialize the store and create the temporary streaming directory.

        The tmp_dir is created immediately (parents=True, exist_ok=True).
        No JSONL files are opened until the first begin_test() call.

        If tools_dir is provided, pin_artifact() will write a copy of each
        sanitized external-tool artifact as a standalone JSON file inside
        that directory (created on first write, best-effort).  This enables
        direct inspection of raw tool output without parsing evidence.json.
        Typical value: config.output.directory / "tools".

        Args:
            tmp_dir:   Path to the temporary directory where per-test JSONL
                       files will be written.  Typically
                       config.output.evidence_tmp_path
                       (e.g. Path("outputs/evidence_tmp")).
            tools_dir: Optional directory where each pin_artifact() call will
                       persist a human-readable JSON copy of the tool's raw
                       output.  Typically config.output.directory / "tools"
                       (e.g. Path("outputs/tools")).  None disables file output.
        """
        self._tmp_dir: Path = tmp_dir
        self._tmp_dir.mkdir(parents=True, exist_ok=True)

        self._tools_dir: Path | None = tools_dir

        # Active state: populated between begin_test() and end_test().
        self._current_test_id: str | None = None
        self._current_file: IO[str] | None = None

        # In-memory mirror of the current test's records.
        # Supports read-interface methods (get_by_id, iter_records) during
        # test execution without re-reading the JSONL file.
        # Cleared on each begin_test() call.
        self._current_buffer: list[EvidenceRecord] = []

        # Running total of records written across ALL completed tests.
        # Updated in end_test() from len(self._current_buffer).
        self._total_records_written: int = 0

        log.debug(
            "evidence_store_initialized",
            tmp_dir=str(tmp_dir),
            tools_dir=str(tools_dir) if tools_dir else None,
            architecture="streaming_jsonl_v2",
        )

    # ------------------------------------------------------------------
    # Read-only accessors (for consumers outside core/)
    # ------------------------------------------------------------------

    @property
    def tools_dir(self) -> Path | None:
        """Read-only path to the external-tool artifact output directory.

        Exposed so that ExternalToolTest._load_dev_cache() can locate the
        cached artifact file for a given label without accessing the private
        ``_tools_dir`` attribute directly.

        Value is set at construction time by engine.py as
        ``config.output.directory / "tools"``.  Returns None if the store was
        initialized without a tools_dir (e.g. in tests that construct
        EvidenceStore directly with a minimal tmp_dir).  Callers must guard
        against None before using the path:

            if store.tools_dir is not None:
                cache_path = store.tools_dir / "my_file.json"

        This property is intentionally read-only: tools_dir is an immutable
        structural parameter of the store, set once at initialization and
        shared across the entire assessment run.

        Returns:
            Path | None: The absolute or relative path passed as ``tools_dir``
            to ``__init__()``, or None if not configured.
        """
        return self._tools_dir

    # ------------------------------------------------------------------
    # Phase-lifecycle interface (called by engine.py only)
    # ------------------------------------------------------------------

    def begin_test(self, test_id: str) -> None:
        """
        Open the per-test JSONL file for streaming writes.

        Must be called by engine.py immediately before each test.execute().
        Calling begin_test() without a preceding end_test() raises RuntimeError.

        The JSONL filename is derived from test_id by replacing characters
        unsafe in filenames (dots, slashes) with underscores:
            "1.1"  -> "1_1.jsonl"
            "4.3"  -> "4_3.jsonl"

        The file is opened in write mode ('w'): each run overwrites any stale
        file from a previous crashed run, guaranteeing idempotent re-runs.

        Args:
            test_id: The test_id ClassVar of the test about to execute,
                     e.g. "1.1", "4.3".

        Raises:
            RuntimeError: If a test is already active (missing end_test call).
            OSError:       If the JSONL file cannot be created.
        """
        if self._current_file is not None:
            raise RuntimeError(
                f"begin_test('{test_id}') called while test "
                f"'{self._current_test_id}' is still active. "
                "end_test() must be called before starting a new test."
            )

        self._current_test_id = test_id
        self._current_buffer = []

        safe_name = self._safe_filename(test_id)
        jsonl_path = self._tmp_dir / f"{safe_name}{_JSONL_EXTENSION}"
        self._current_file = jsonl_path.open("w", encoding="utf-8")

        log.debug(
            "evidence_store_test_started",
            test_id=test_id,
            jsonl_path=str(jsonl_path),
        )

    def end_test(self) -> None:
        """
        Flush and close the current per-test JSONL file.

        Must be called by engine.py immediately after each test.execute()
        returns -- including in error/exception paths (the engine's try/finally
        must cover this call so no file handle is left dangling).

        Updates _total_records_written with the count from the completed test.

        Raises:
            RuntimeError: If no test is currently active.
            OSError:       If the file flush/close fails.
        """
        if self._current_file is None:
            raise RuntimeError(
                "end_test() called with no active test. begin_test() must be called first."
            )

        self._current_file.flush()
        self._current_file.close()
        self._current_file = None

        records_this_test = len(self._current_buffer)
        self._total_records_written += records_this_test

        log.debug(
            "evidence_store_test_completed",
            test_id=self._current_test_id,
            records_this_test=records_this_test,
            total_records_written=self._total_records_written,
        )

        self._current_test_id = None
        self._current_buffer = []

    def merge_and_finalize(self, output_path: Path) -> int:
        """
        Merge all per-test JSONL files into a single evidence.json and clean up.

        Called once by engine.py at the start of Phase 7, after the last
        end_test() and before any report rendering.

        Algorithm:
            1. Glob all *.jsonl files from the tmp directory (sorted by name
               for deterministic ordering before the timestamp sort).
            2. Deserialize each line into an EvidenceRecord via Pydantic v2.
            3. Sort all records chronologically by timestamp_utc.
            4. Write evidence.json with the same envelope format as v1.0
               for full backward compatibility with the HTML report template.
            5. Remove the tmp directory (shutil.rmtree) -- log WARNING on
               failure but do not propagate (cleanup issue, not data loss).

        If no JSONL files exist (zero evidence recorded during the run),
        writes a valid evidence.json with an empty records array.

        Args:
            output_path: Destination path for evidence.json.
                         Typically config.output.evidence_path.

        Returns:
            int: Total number of records written to evidence.json.

        Raises:
            OSError: If evidence.json cannot be written.  Propagated to the
                     engine, which logs and continues (report is non-fatal).
        """
        if self._current_file is not None:
            log.warning(
                "evidence_store_merge_called_with_active_test",
                active_test_id=self._current_test_id,
                detail=(
                    "merge_and_finalize() was called while a test JSONL file "
                    "was still open.  Closing it now as a safety measure."
                ),
            )
            self.end_test()

        all_records: list[EvidenceRecord] = []
        jsonl_files = sorted(self._tmp_dir.glob(f"*{_JSONL_EXTENSION}"))

        log.info(
            "evidence_store_merge_started",
            jsonl_file_count=len(jsonl_files),
            output_path=str(output_path),
        )

        for jsonl_path in jsonl_files:
            file_records = self._read_jsonl_file(jsonl_path)
            all_records.extend(file_records)
            log.debug(
                "evidence_store_merge_file_read",
                file=jsonl_path.name,
                record_count=len(file_records),
            )

        all_records.sort(key=lambda r: r.timestamp_utc)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        serializable = [r.model_dump(mode="json") for r in all_records]

        output_payload: dict[str, object] = {
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "record_count": len(all_records),
            "records": serializable,
        }

        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(output_payload, fh, indent=2, ensure_ascii=False)

        log.info(
            "evidence_store_merge_completed",
            output_path=str(output_path),
            total_records=len(all_records),
        )

        try:
            shutil.rmtree(self._tmp_dir)
            log.debug(
                "evidence_store_tmp_dir_removed",
                tmp_dir=str(self._tmp_dir),
            )
        except OSError as exc:
            log.warning(
                "evidence_store_tmp_dir_removal_failed",
                tmp_dir=str(self._tmp_dir),
                detail=str(exc),
            )

        return len(all_records)

    # ------------------------------------------------------------------
    # Write interface (called by tests -- unchanged from v1.0)
    # ------------------------------------------------------------------

    def add_fail_evidence(self, record: EvidenceRecord) -> None:
        """
        Record an HTTP transaction that produced a FAIL outcome.

        Primary write path.  Every transaction where the observed server
        behavior violates the security guarantee under test must be recorded
        here.  The record constitutes the demonstrable proof of the
        vulnerability and will appear in the final evidence.json.

        The record is serialized immediately as a single JSON line in the
        current per-test JSONL file and flushed to disk.  Memory footprint
        is O(1) per call regardless of total evidence volume -- no eviction,
        no data loss.

        Must be called between begin_test() and end_test().

        Args:
            record: The EvidenceRecord representing the failing HTTP transaction.
                    Must have been constructed by SecurityClient, which enforces
                    Authorization header redaction before storage.

        Raises:
            RuntimeError: If called outside an active test context.
        """
        self._require_active_test("add_fail_evidence")
        self._write_record(record)
        log.debug(
            "evidence_record_added",
            record_id=record.record_id,
            request_method=record.request_method,
            request_url=record.request_url,
            response_status_code=record.response_status_code,
            test_id=self._current_test_id,
        )

    def pin_evidence(self, record: EvidenceRecord) -> None:
        """
        Record an HTTP transaction explicitly marked as key evidence by a test.

        Pinned records are stored even when they did not directly produce a
        FAIL outcome.  Used for setup transactions that establish the context
        of a subsequent attack (e.g., the login response that issued the token
        later used in a BOLA cross-ownership test).

        A copy of the record with is_pinned=True is written.  Since
        EvidenceRecord is frozen (immutable), the copy is created via
        model_copy(update=...) from Pydantic v2, returning a new instance
        without mutating the original.

        Must be called between begin_test() and end_test().

        Args:
            record: The EvidenceRecord to pin.  is_pinned will be forced to
                    True regardless of its value in the incoming record.

        Raises:
            RuntimeError: If called outside an active test context.
        """
        self._require_active_test("pin_evidence")
        pinned_record = record.model_copy(update={"is_pinned": True})
        self._write_record(pinned_record)
        log.debug(
            "evidence_record_pinned",
            record_id=pinned_record.record_id,
            request_method=pinned_record.request_method,
            request_url=pinned_record.request_url,
            test_id=self._current_test_id,
        )

    def pin_artifact(self, label: str, data: dict[str, Any]) -> str:
        """
        Serialize and persist an arbitrary JSON artifact from an external tool.

        External Tool Tests (ExternalToolTest subclasses) do not produce
        EvidenceRecord objects -- they produce raw JSON output from binaries
        such as ffuf, testssl.sh, or nuclei.  This method wraps that output
        in a synthetic EvidenceRecord so it enters the same evidence.json
        output as native HTTP evidence, maintaining a single audit trail.

        Sanitization is applied to the artifact payload before storage.
        Tool outputs can embed partial HTTP responses containing Authorization
        headers, Bearer tokens, cookies, or API keys captured during scanning.
        The _sanitize_artifact() method performs a recursive string scan on
        the dict and replaces values matching known credential patterns with
        "[REDACTED]".  This sanitization is the responsibility of EvidenceStore,
        not of the calling test -- "security by default" over "security by
        convention".

        Disk persistence (outputs/tools/):
            If the store was initialized with a tools_dir, a copy of the
            sanitized payload is written to:
                tools_dir/<label_safe>.json
            where label_safe replaces dots, slashes and spaces with underscores.
            Write failures are logged as WARNING and never propagate -- a failed
            disk write must not abort the assessment.

        The returned evidence_ref string is the record_id of the synthetic
        EvidenceRecord.  The calling test should attach it to the relevant
        Finding.evidence_ref field to cross-reference the artifact.

        Must be called between begin_test() and end_test().

        Args:
            label: Short human-readable label for the artifact, used as the
                   request_method field of the synthetic record for display
                   purposes.  Example: "ffuf_shadow_api_scan".
            data:  Arbitrary dict produced by the external tool's JSON output
                   (e.g., ConnectorResult.raw_output).  Will be sanitized
                   before storage.

        Returns:
            str: The record_id of the written synthetic EvidenceRecord,
                 suitable for assignment to Finding.evidence_ref.

        Raises:
            RuntimeError: If called outside an active test context (between
                          begin_test() and end_test()).
        """
        self._require_active_test("pin_artifact")
        sanitized: dict[str, Any] = self._sanitize_artifact(data)
        record_id: str = (
            f"artifact-{self._current_test_id}-{label}-{datetime.now(UTC).strftime('%H%M%S%f')}"
        )
        # Synthetic EvidenceRecord: we repurpose the HTTP-centric fields
        # to carry artifact metadata.  request_method holds the label so the
        # HTML report can display it as the "operation" column.
        # request_url encodes the test_id for traceability (format matches
        # record_id, which already contains self._current_test_id).
        synthetic_record = EvidenceRecord(
            record_id=record_id,
            timestamp_utc=datetime.now(UTC),
            request_method=label.upper(),
            request_url=f"external://{self._current_test_id}/{label}",
            request_headers={},
            request_body=None,
            response_status_code=0,
            response_headers={},
            response_body=json.dumps(sanitized, ensure_ascii=False),
            is_pinned=True,
        )
        self._write_record(synthetic_record)

        # --- Optional disk persistence for direct inspection ---
        # Best-effort: a write failure must never abort the assessment.
        if self._tools_dir is not None:
            self._persist_tool_artifact(label=label, record_id=record_id, payload=sanitized)

        log.debug(
            "evidence_artifact_pinned",
            record_id=record_id,
            label=label,
            test_id=self._current_test_id,
        )
        return record_id

    def _persist_tool_artifact(
        self,
        label: str,
        record_id: str,
        payload: dict[str, Any],
    ) -> None:
        """
        Write a sanitized tool artifact as a standalone JSON file to tools_dir.

        Called internally by pin_artifact() when self._tools_dir is not None.
        Never raises: all OSError exceptions are caught and logged as WARNING.

        File naming: tool_output_<testId_safe>.json, where testId_safe replaces
        characters unsafe in filenames (dots, slashes, backslashes, spaces) with
        underscores.  The prefix ``tool_output_`` and the test_id (not the
        label) are used so that the filename matches exactly what the HTML
        report's "Download as JSON" button produces in the browser, giving the
        operator a 1:1 correspondence between disk artefacts and downloads.

        Example: test_id "ext.0.1" → file "tool_output_ext_0_1.json".

        The envelope structure mirrors the one reconstructed by the HTML
        template's export function so that the two files are content-identical
        (modulo generated_at_utc: the disk file records creation time, the
        browser download records the time the operator clicked Export).

        Args:
            label:     Human-readable label passed to pin_artifact().
            record_id: The evidence record_id returned by pin_artifact(),
                       embedded in the JSON envelope for cross-referencing.
            payload:   Already-sanitized dict to write.
        """
        assert self._tools_dir is not None  # noqa: S101 -- caller guarantees this

        # The label already encodes both the test_id and the tool name
        # (e.g. "ext.0.1_nuclei", "ext.1.5_testssl_sh"), so sanitising it
        # produces a filename that is:
        #   - sorted by domain/test number (ext_0_1_... comes before ext_1_5_...)
        #   - immediately identifiable by tool name without opening the file
        #   - distinguished from other artefacts by the _output suffix
        # Example mappings:
        #   "ext.0.1_nuclei"    -> "ext_0_1_nuclei_output.json"
        #   "ext.1.5_testssl_sh"-> "ext_1_5_testssl_sh_output.json"
        safe_label: str = label
        for char in _ARTIFACT_FILENAME_UNSAFE_CHARS:
            safe_label = safe_label.replace(char, "_")
        file_path = self._tools_dir / f"{safe_label}_output.json"

        # Envelope structure mirrors the one the HTML report's "Download as JSON"
        # button reconstructs client-side, ensuring disk file and browser download
        # are structurally identical.  The only expected difference is
        # generated_at_utc: the disk file records the moment of pipeline
        # execution; the browser download records the moment the operator clicks
        # Export.
        envelope: dict[str, Any] = {
            "source_test_id": self._current_test_id,
            "label": label,
            "record_id": record_id,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "data": payload,
        }

        try:
            self._tools_dir.mkdir(parents=True, exist_ok=True)
            file_path.write_text(
                json.dumps(envelope, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            log.info(
                "evidence_artifact_persisted_to_disk",
                record_id=record_id,
                label=label,
                path=str(file_path),
            )
        except OSError as exc:
            log.warning(
                "evidence_artifact_disk_write_failed",
                record_id=record_id,
                label=label,
                path=str(file_path),
                detail=str(exc),
            )

    @staticmethod
    def _sanitize_artifact(data: dict[str, Any]) -> dict[str, Any]:
        """
        Recursively sanitize a dict by redacting credential-like string values.

        Scans every string value in the dict (including nested dicts and lists)
        and replaces it with "[REDACTED]" if it matches any of the following
        credential patterns:
            - Keys where any of the following appear as whole words or compound
              components (separated by -, _, ., space, or string boundaries):
              "token", "password", "api_key", "apikey", "authorization",
              "bearer", "secret", "credential", "auth".
              Word-boundary matching prevents false positives: "author" is NOT
              redacted (auth is a prefix letter-run), while "auth_token",
              "x-auth-token", and "authorization" ARE redacted.
            - String values whose content starts with "Bearer ", "Basic ",
              "Token ", or "token " (Authorization header leakage).
            - String values matching the pattern of a JWT (three base64url
              segments separated by dots, total length > 40 characters).

        Scope: credentials only.  Filesystem path normalization is NOT
        performed here -- that responsibility belongs exclusively to the
        connector layer (BaseSubprocessConnector._relativize_display_path for
        CLI command strings, _sanitize_paths_in_findings for per-field paths
        within tool output).  Any absolute infrastructure path in the artifact
        has already been relativized before pin_artifact() is called; any
        remaining path-like value is finding data from the target system and
        must be preserved verbatim.

        The method returns a NEW dict -- the original is never mutated.
        Non-string values (int, float, bool, None) are copied unchanged.

        Args:
            data: The dict to sanitize. May contain nested dicts and lists.

        Returns:
            dict[str, Any]: A deep copy of the input with credentials redacted.
        """

        def _redact_value(key: str, value: Any) -> Any:  # noqa: ANN401
            """Redact value if key or value content indicates a credential."""
            lower_key = key.lower()
            # Word-boundary match via _SENSITIVE_KEY_RE: prevents false positives
            # such as "author" being redacted because "auth" is a bare substring.
            # The regex requires that each pattern is surrounded by non-letter
            # chars (separators or string boundaries) -- see module-level comment.
            if _SENSITIVE_KEY_RE.search(lower_key):
                return "[REDACTED]"
            if isinstance(value, str):
                if any(value.startswith(pfx) for pfx in _SANITIZE_HEADER_PREFIXES):
                    return "[REDACTED]"
                if len(value) > 40 and _SANITIZE_JWT_PATTERN.match(value):
                    return "[REDACTED]"
            return value

        def _walk(obj: Any, parent_key: str = "") -> Any:  # noqa: ANN401
            if isinstance(obj, dict):
                return {k: _walk(_redact_value(k, v), k) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_walk(item, parent_key) for item in obj]
            return obj

        return _walk(data)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Read interface (called by tests -- unchanged from v1.0)
    # ------------------------------------------------------------------

    @property
    def record_count(self) -> int:
        """
        Total evidence records written across all completed tests plus the
        current active test's in-memory buffer.

        Surfaced in the engine's Phase 7 log line ('evidence_records') and
        in the HTML report's executive summary stat card.
        """
        return self._total_records_written + len(self._current_buffer)

    @property
    def is_empty(self) -> bool:
        """True if no evidence records have been written during this run."""
        return self.record_count == 0

    def get_by_id(self, record_id: str) -> EvidenceRecord | None:
        """
        Retrieve a specific record from the current test's in-memory buffer.

        Scoped to the active test only -- does not scan JSONL files from
        completed tests.  Used by tests that need to cross-reference an
        earlier transaction within the same test execution.

        For post-run cross-test lookups, use evidence.json after Phase 7.

        Args:
            record_id: The record_id to search for, e.g. "1.2_001".

        Returns:
            The matching EvidenceRecord from the current buffer, or None.
        """
        for record in self._current_buffer:
            if record.record_id == record_id:
                return record
        return None

    def iter_records(self) -> Iterator[EvidenceRecord]:
        """
        Iterate over all records in the current test's in-memory buffer.

        Scoped to the active test only, in insertion order (oldest first).

        Yields:
            EvidenceRecord objects from the current test's buffer.
        """
        yield from self._current_buffer

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_active_test(self, method_name: str) -> None:
        """
        Assert that a test is currently active (between begin_test/end_test).

        Produces a clear error message when the engine fails to bracket test
        execution with the correct lifecycle calls.

        Args:
            method_name: Name of the calling public method, for the message.

        Raises:
            RuntimeError: If no test is currently active.
        """
        if self._current_file is None:
            raise RuntimeError(
                f"EvidenceStore.{method_name}() called outside an active test. "
                "engine.py must call begin_test(test_id) before test.execute() "
                "and end_test() after it returns."
            )

    def _write_record(self, record: EvidenceRecord) -> None:
        """
        Serialize a record as one JSON line and flush to the current JSONL file.

        Uses Pydantic v2's model_dump(mode='json') for correct serialization
        of datetime -> ISO 8601 string and enum -> str value.  One object per
        line (JSONL format): each line is independently parseable by
        _read_jsonl_file() during the merge step.

        Also appends to the in-memory buffer so that read-interface methods
        (get_by_id, iter_records) work correctly during test execution.

        Args:
            record: The EvidenceRecord to persist.

        Raises:
            OSError: If the write or flush fails (disk full, permission error).
        """
        assert self._current_file is not None  # noqa: S101 -- guarded by _require_active_test
        line = json.dumps(record.model_dump(mode="json"), ensure_ascii=False)
        self._current_file.write(line + "\n")
        self._current_file.flush()
        self._current_buffer.append(record)

    @staticmethod
    def _safe_filename(test_id: str) -> str:
        """
        Convert a test_id to a filesystem-safe filename stem.

        Replaces dots and slashes with underscores:
            "1.1"  -> "1_1"
            "4.3"  -> "4_3"

        Args:
            test_id: Raw test identifier string (e.g. "1.1", "4.3").

        Returns:
            A string safe for use as a filename stem on all major filesystems.
        """
        safe = test_id
        for char in _TEST_ID_UNSAFE_CHARS:
            safe = safe.replace(char, "_")
        return safe

    @staticmethod
    def _read_jsonl_file(path: Path) -> list[EvidenceRecord]:
        """
        Read and deserialize all EvidenceRecord objects from a JSONL file.

        Skips blank lines (e.g. trailing newline added by _write_record).
        Logs a WARNING for any line that fails to parse and continues --
        a corrupt line in one test's file must not suppress evidence from
        all other tests in the final report.

        Args:
            path: Filesystem path to the *.jsonl file to read.

        Returns:
            List of EvidenceRecord objects in file order (insertion order
            within the test that wrote them).
        """
        records: list[EvidenceRecord] = []
        try:
            raw_lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            log.warning(
                "evidence_store_jsonl_read_error",
                file=str(path),
                detail=str(exc),
            )
            return records

        for line_number, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
                records.append(EvidenceRecord.model_validate(data))
            except (json.JSONDecodeError, ValueError) as exc:
                log.warning(
                    "evidence_store_jsonl_line_parse_error",
                    file=path.name,
                    line_number=line_number,
                    detail=str(exc),
                )

        return records
