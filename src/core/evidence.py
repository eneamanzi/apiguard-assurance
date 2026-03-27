"""
src/core/evidence.py

EvidenceStore: selective in-memory buffer for HTTP transaction evidence.

The store maintains a bounded FIFO deque of EvidenceRecord objects.
It does NOT record every HTTP transaction performed during the assessment.
It records only transactions that meet at least one of two criteria:

    1. The transaction produced a FAIL outcome (mandatory evidence of violation).
    2. The test explicitly pinned the transaction as key evidence (e.g., a
       setup request that establishes the context for a subsequent attack).

This selective recording policy solves two problems simultaneously:
    - Memory safety: the deque bound prevents OOM on high-volume tests
      (e.g., Test 4.1 rate-limit discovery emits up to 150 requests).
    - Evidence quality: the output evidence.json contains only transactions
      that an analyst needs to read, not a raw HTTP log.

At the end of Phase 7, the engine calls to_json_file() to persist the
entire buffer to evidence.json as the permanent, demonstrable audit record.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import structlog

from src.core.models import EvidenceRecord

# Module-level logger. Bound context (test_id, etc.) is added at call sites.
log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum number of EvidenceRecord objects retained in memory at any time.
# Rationale (Implementazione.md, Section 4.4): worst-case assessment produces
# ~50 relevant records (26 tests * 50% fail rate * 2-3 findings each).
# A limit of 100 provides >100% safety margin without risking OOM.
EVIDENCE_BUFFER_MAX_SIZE: int = 100

# Maximum length of response_body stored per record, in characters.
# Defined here as a documentation anchor; the actual truncation is enforced
# by EvidenceRecord's field_validator in models.py.
RESPONSE_BODY_MAX_CHARS: int = 10_000

# Default output filename for the serialized evidence archive.
EVIDENCE_OUTPUT_FILENAME: str = "evidence.json"


# ---------------------------------------------------------------------------
# EvidenceStore
# ---------------------------------------------------------------------------


class EvidenceStore:
    """
    Selective in-memory buffer for HTTP transaction evidence.

    The store wraps a collections.deque with maxlen=EVIDENCE_BUFFER_MAX_SIZE.
    When the buffer is full, Python's deque implementation automatically
    evicts the oldest record (popleft) before inserting the new one. This
    O(1) eviction requires no explicit garbage collection logic here.

    Thread safety: this class is NOT thread-safe. The tool is designed for
    strictly sequential execution (Implementazione.md, Section 4.3), so no
    locking mechanism is needed or provided. Introducing parallelism in a
    future version would require wrapping mutations in a threading.Lock.

    Usage pattern (inside a BaseTest.execute() implementation):

        # Mandatory: record a transaction that produced a FAIL
        store.add_fail_evidence(record)

        # Optional: pin a setup transaction as key context
        store.pin_evidence(record)

        # Read-only: check current buffer state
        count = store.record_count
    """

    def __init__(self) -> None:
        """
        Initialize an empty EvidenceStore with a bounded FIFO deque.

        The deque's maxlen is set at construction time and cannot be changed
        afterward. This immutability of the buffer bound is intentional: a
        store whose capacity can be altered at runtime would make the OOM
        safety guarantee non-deterministic.
        """
        self._buffer: deque[EvidenceRecord] = deque(maxlen=EVIDENCE_BUFFER_MAX_SIZE)
        log.debug(
            "evidence_store_initialized",
            buffer_max_size=EVIDENCE_BUFFER_MAX_SIZE,
        )

    # ------------------------------------------------------------------
    # Write interface
    # ------------------------------------------------------------------

    def add_fail_evidence(self, record: EvidenceRecord) -> None:
        """
        Record an HTTP transaction that produced a FAIL outcome.

        This is the primary write path. Every transaction where the observed
        server behavior violates the security guarantee under test must be
        recorded here. The record constitutes the demonstrable proof of the
        vulnerability.

        The record is stored as-is (EvidenceRecord is frozen). If the buffer
        is full, the oldest record is automatically evicted by the deque.
        A WARNING is emitted when eviction occurs, because losing an older
        FAIL evidence record is a condition worth surfacing in the log.

        Args:
            record: The EvidenceRecord representing the failing HTTP transaction.
                    Must have been constructed by SecurityClient, which enforces
                    Authorization header redaction before storage.
        """
        was_full = len(self._buffer) == EVIDENCE_BUFFER_MAX_SIZE

        self._buffer.append(record)

        if was_full:
            log.warning(
                "evidence_buffer_full_eviction_occurred",
                buffer_max_size=EVIDENCE_BUFFER_MAX_SIZE,
                evicted_to_make_room_for=record.record_id,
                detail=(
                    "The oldest evidence record was evicted to make room. "
                    "Consider reviewing EVIDENCE_BUFFER_MAX_SIZE if this "
                    "occurs frequently during an assessment run."
                ),
            )
        else:
            log.debug(
                "evidence_record_added",
                record_id=record.record_id,
                request_method=record.request_method,
                request_url=record.request_url,
                response_status_code=record.response_status_code,
                buffer_size_after=len(self._buffer),
            )

    def pin_evidence(self, record: EvidenceRecord) -> None:
        """
        Record an HTTP transaction explicitly marked as key evidence by a test.

        Pinned records are stored even when they did not directly produce a
        FAIL outcome. This is used for setup transactions that establish the
        context of a subsequent attack (e.g., the login response that issued
        the token later used in a BOLA test).

        Internally, pinning works by appending a copy of the record with
        is_pinned=True. Since EvidenceRecord is frozen (immutable), the copy
        is created via model_copy(update=...) from Pydantic v2, which returns
        a new instance without mutating the original.

        The same eviction warning logic as add_fail_evidence applies.

        Args:
            record: The EvidenceRecord to pin. is_pinned will be forced to
                    True regardless of its value in the incoming record.
        """
        pinned_record = record.model_copy(update={"is_pinned": True})

        was_full = len(self._buffer) == EVIDENCE_BUFFER_MAX_SIZE
        self._buffer.append(pinned_record)

        if was_full:
            log.warning(
                "evidence_buffer_full_eviction_on_pin",
                buffer_max_size=EVIDENCE_BUFFER_MAX_SIZE,
                pinned_record_id=pinned_record.record_id,
            )
        else:
            log.debug(
                "evidence_record_pinned",
                record_id=pinned_record.record_id,
                request_method=pinned_record.request_method,
                request_url=pinned_record.request_url,
                buffer_size_after=len(self._buffer),
            )

    # ------------------------------------------------------------------
    # Read interface
    # ------------------------------------------------------------------

    @property
    def record_count(self) -> int:
        """Current number of records in the buffer."""
        return len(self._buffer)

    @property
    def is_empty(self) -> bool:
        """True if no records have been stored yet."""
        return len(self._buffer) == 0

    def get_by_id(self, record_id: str) -> EvidenceRecord | None:
        """
        Retrieve a specific record by its record_id.

        This is a linear scan — O(n) on buffer size. It is called only during
        report generation (Phase 7), never in the hot path of test execution,
        so the performance characteristic is acceptable.

        Args:
            record_id: The record_id to search for, e.g. "1.2_001".

        Returns:
            The matching EvidenceRecord, or None if not found.
        """
        for record in self._buffer:
            if record.record_id == record_id:
                return record
        return None

    def iter_records(self) -> Iterator[EvidenceRecord]:
        """
        Iterate over all records in insertion order (oldest to newest).

        Returns an iterator rather than a copy of the list to avoid
        allocating a second buffer-sized collection during report generation.
        The caller must not mutate the store during iteration.

        Yields:
            EvidenceRecord objects in FIFO order.
        """
        yield from self._buffer

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def to_json_file(self, output_path: Path) -> int:
        """
        Serialize the entire buffer to a JSON file at the given path.

        The output is a JSON array of objects, one per EvidenceRecord,
        ordered by timestamp_utc (oldest first). Each object is the full
        Pydantic model serialized via model_dump(mode="json"), which handles
        datetime serialization to ISO 8601 strings and enum serialization
        to their string values.

        This method is called once at the end of Phase 7, after all tests
        and teardown have completed. It is the terminal write operation of
        the pipeline and produces the permanent audit record.

        The output directory is created if it does not exist, using
        parents=True and exist_ok=True to avoid race conditions on first run.

        Args:
            output_path: Filesystem path for the output file.
                         Typically Path("evidence.json") in the working directory.

        Returns:
            int: Number of records written to the file.

        Raises:
            OSError: If the file cannot be written (permission denied,
                     filesystem full, etc.). Not wrapped in a ToolBaseError
                     because this is a genuine filesystem-level error that
                     the caller (engine.py) should surface directly.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Sort by timestamp_utc to produce a chronological audit trail.
        # The deque preserves insertion order, which is already chronological
        # for sequential execution. The explicit sort is a defensive measure
        # against any future parallelism introducing out-of-order insertions.
        sorted_records = sorted(
            self._buffer,
            key=lambda r: r.timestamp_utc,
        )

        # Serialize using Pydantic v2's model_dump(mode="json").
        # mode="json" ensures datetime -> ISO 8601 string, Enum -> str value.
        serializable_records = [record.model_dump(mode="json") for record in sorted_records]

        # Build the top-level envelope with metadata for traceability.
        output_payload: dict[str, object] = {
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "record_count": len(sorted_records),
            "buffer_max_size": EVIDENCE_BUFFER_MAX_SIZE,
            "records": serializable_records,
        }

        with output_path.open("w", encoding="utf-8") as file_handle:
            json.dump(output_payload, file_handle, indent=2, ensure_ascii=False)

        log.info(
            "evidence_serialized_to_file",
            output_path=str(output_path),
            record_count=len(sorted_records),
        )

        return len(sorted_records)
