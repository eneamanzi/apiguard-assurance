"""
tests_integration/test_06_teardown.py

Phase 6 — Teardown (Best-Effort): Executable Documentation for the cleanup loop.

This file documents the contracts of the engine's _phase_6_teardown() method:
how it drains the TestContext resource registry in LIFO order, how it delegates
DELETE requests to SecurityClient, how it handles failures (TeardownError,
unexpected exceptions), and how cleanup results are isolated from the assessment
outcome.

Key architectural guarantee documented here
-------------------------------------------
A teardown failure NEVER affects the ResultSet, the exit code, or the assessment
outcome. Phase 6 is explicitly "best-effort": cleaning up test-created resources
is important for hygiene, but missing cleanup does not invalidate the findings.

Isolation strategy
------------------
SecurityClient is replaced by a MagicMock whose `request` method can be
configured to return arbitrary (response, record) tuples or to raise exceptions.
This avoids opening TCP connections while still exercising all teardown paths.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from src.core.context import TargetContext, TestContext
from src.engine import AssessmentEngine

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_engine(minimal_config_file: Path) -> AssessmentEngine:
    return AssessmentEngine(config_path=minimal_config_file)


def _mock_target() -> TargetContext:
    t = MagicMock(spec=TargetContext)
    t.endpoint_base_url.return_value = "http://localhost:8000"
    return t


def _stub_response(status_code: int) -> MagicMock:
    """Return a minimal httpx.Response-like mock with a given status_code."""
    resp = MagicMock()
    resp.status_code = status_code
    return resp


def _make_client(status_code: int = 204) -> MagicMock:
    """
    Return a SecurityClient mock whose request() returns (response, evidence_record).

    The evidence_record is a plain MagicMock — teardown does not interact with
    the EvidenceStore, so its exact type is irrelevant here.
    """
    client = MagicMock()
    client.request.return_value = (_stub_response(status_code), MagicMock())
    return client


# ===========================================================================
# Section A — Empty registry
# ===========================================================================


class TestTeardownEmptyRegistry:
    """
    When no resources were registered during Phase 5, Phase 6 must complete
    immediately and without making any HTTP requests.

    An empty teardown is the happy path for assessments whose tests do not
    create persistent resources (e.g., read-only BLACK_BOX tests).
    """

    def test_empty_registry_makes_no_http_requests(self, minimal_config_file: Path) -> None:
        """
        Zero registered resources → zero DELETE requests issued.

        SecurityClient.request() must not be called when the registry is empty.
        Calling DELETE on a non-existent resource would be a correctness error.
        """
        client = _make_client()
        context = TestContext()
        engine = _build_engine(minimal_config_file)

        engine._phase_6_teardown(
            context=context,
            client=client,
            target=_mock_target(),
        )

        client.request.assert_not_called()

    def test_empty_registry_does_not_raise(self, minimal_config_file: Path) -> None:
        """
        An empty resource registry must not raise any exception.

        Phase 6 must be callable even when the preceding Phase 5 ran no tests
        or no test registered any resource. The engine calls teardown
        unconditionally after Phase 5.
        """
        context = TestContext()
        engine = _build_engine(minimal_config_file)

        # Must not raise
        engine._phase_6_teardown(
            context=context,
            client=_make_client(),
            target=_mock_target(),
        )

    def test_registry_is_empty_after_teardown(self, minimal_config_file: Path) -> None:
        """
        After teardown, registered_resource_count() must return 0.

        drain_resources() is called once and clears the internal list.
        A subsequent call to registered_resource_count() must reflect the
        empty state, preventing phantom cleanups if teardown were called twice.
        """
        context = TestContext()
        engine = _build_engine(minimal_config_file)

        engine._phase_6_teardown(
            context=context,
            client=_make_client(),
            target=_mock_target(),
        )

        assert context.registered_resource_count() == 0


# ===========================================================================
# Section B — LIFO ordering
# ===========================================================================


class TestTeardownLIFOOrdering:
    """
    The resource registry must be drained in LIFO (Last In, First Out) order.

    LIFO ensures that resources with implicit creation dependencies are deleted
    in the correct reverse order. For example, if a test creates a user and then
    a repository owned by that user, the repository must be deleted before the user.

    This ordering guarantee is part of the TestContext.drain_resources() contract,
    which Phase 6 relies on. These tests verify that the engine calls
    drain_resources() and iterates the returned list in the order provided.
    """

    def test_two_resources_deleted_in_lifo_order(self, minimal_config_file: Path) -> None:
        """
        Two registered resources are cleaned up in reverse registration order.

        Registration order: /api/v1/users/1  →  /api/v1/repos/1
        Expected DELETE order: /api/v1/repos/1  →  /api/v1/users/1
        """
        context = TestContext()
        context.register_resource_for_teardown("DELETE", "/api/v1/users/1")
        context.register_resource_for_teardown("DELETE", "/api/v1/repos/1")

        client = _make_client(status_code=204)
        engine = _build_engine(minimal_config_file)

        engine._phase_6_teardown(
            context=context,
            client=client,
            target=_mock_target(),
        )

        actual_calls = [c.kwargs["path"] for c in client.request.call_args_list]
        assert actual_calls == ["/api/v1/repos/1", "/api/v1/users/1"], (
            f"Expected LIFO order [repos, users], got {actual_calls}"
        )

    def test_three_resources_deleted_in_full_lifo_order(self, minimal_config_file: Path) -> None:
        """
        Three resources are deleted in strict reverse-registration order.

        Registration sequence: /a → /b → /c
        Expected DELETE sequence: /c → /b → /a
        """
        context = TestContext()
        for path in ["/a", "/b", "/c"]:
            context.register_resource_for_teardown("DELETE", path)

        client = _make_client(status_code=204)
        engine = _build_engine(minimal_config_file)

        engine._phase_6_teardown(
            context=context,
            client=client,
            target=_mock_target(),
        )

        actual_paths = [c.kwargs["path"] for c in client.request.call_args_list]
        assert actual_paths == ["/c", "/b", "/a"]

    def test_one_request_per_registered_resource(self, minimal_config_file: Path) -> None:
        """
        Exactly one DELETE request is issued per registered resource.

        The engine must not issue double-deletes (idempotency is irrelevant
        here — DELETE twice on the same path would fail if the resource was
        already removed by the first call).
        """
        context = TestContext()
        context.register_resource_for_teardown("DELETE", "/api/v1/items/42")
        context.register_resource_for_teardown("DELETE", "/api/v1/items/99")

        client = _make_client(status_code=200)
        engine = _build_engine(minimal_config_file)

        engine._phase_6_teardown(
            context=context,
            client=client,
            target=_mock_target(),
        )

        assert client.request.call_count == 2, (
            f"Expected exactly 2 DELETE requests, got {client.request.call_count}"
        )


# ===========================================================================
# Section C — Acceptable HTTP status codes
# ===========================================================================


class TestTeardownAcceptableStatusCodes:
    """
    The engine treats 200, 204, and 404 as successful teardown responses.

    - 200 OK: Some APIs return the deleted resource representation.
    - 204 No Content: Standard REST DELETE success.
    - 404 Not Found: The resource was already gone (idempotent delete).

    Any other status code triggers a TeardownError, which is caught and
    logged as WARNING without halting the teardown loop.
    """

    @pytest.mark.parametrize("status_code", [200, 204, 404])
    def test_acceptable_status_codes_do_not_raise(
        self, status_code: int, minimal_config_file: Path
    ) -> None:
        """
        Status codes 200, 204, and 404 are accepted without raising TeardownError.

        All three must be treated as successful cleanup. The test verifies that
        the engine does not log a WARNING for these cases (which would incorrectly
        suggest manual cleanup is required).
        """
        context = TestContext()
        context.register_resource_for_teardown("DELETE", "/api/v1/items/1")

        client = _make_client(status_code=status_code)
        engine = _build_engine(minimal_config_file)

        # Must not raise even if it internally triggers TeardownError
        engine._phase_6_teardown(
            context=context,
            client=client,
            target=_mock_target(),
        )

        # The client must have been called exactly once
        assert client.request.call_count == 1


# ===========================================================================
# Section D — Best-effort failure handling
# ===========================================================================


class TestTeardownBestEffort:
    """
    Phase 6 is explicitly best-effort: failures are logged as WARNING and
    execution continues with the next resource. A teardown failure must
    never propagate as an exception to the caller (the engine's _run_pipeline).

    This is the most critical guarantee of Phase 6: cleanup failures must not
    invalidate an otherwise successful assessment.
    """

    def test_unexpected_status_code_does_not_raise(self, minimal_config_file: Path) -> None:
        """
        An unexpected DELETE status code (e.g., 500) is caught and logged.

        Internally, the engine raises TeardownError and immediately catches it.
        _phase_6_teardown must not propagate this exception to its caller.
        """
        context = TestContext()
        context.register_resource_for_teardown("DELETE", "/api/v1/items/1")

        client = _make_client(status_code=500)  # unexpected → TeardownError
        engine = _build_engine(minimal_config_file)

        # Must not raise
        engine._phase_6_teardown(
            context=context,
            client=client,
            target=_mock_target(),
        )

    def test_teardown_continues_after_single_failure(self, minimal_config_file: Path) -> None:
        """
        A failed DELETE on one resource does not abort the remaining teardown.

        If three resources are registered and the first DELETE returns 500,
        the engine must still attempt to DELETE the remaining two resources.

        This ensures that a partial infrastructure failure leaves as few
        dangling resources as possible.
        """
        context = TestContext()
        context.register_resource_for_teardown("DELETE", "/api/v1/users/1")
        context.register_resource_for_teardown("DELETE", "/api/v1/repos/bad")
        context.register_resource_for_teardown("DELETE", "/api/v1/repos/ok")

        # LIFO order: /repos/ok → /repos/bad → /users/1
        # /repos/bad returns 500 (unexpected); others return 204
        def side_effect(**kwargs: object) -> tuple[MagicMock, MagicMock]:
            path = kwargs.get("path", "")
            status = 500 if path == "/api/v1/repos/bad" else 204
            return (_stub_response(status), MagicMock())

        client = MagicMock()
        client.request.side_effect = side_effect

        engine = _build_engine(minimal_config_file)

        engine._phase_6_teardown(
            context=context,
            client=client,
            target=_mock_target(),
        )

        # All three DELETE attempts must have been made
        assert client.request.call_count == 3, (
            "Teardown must attempt all resources regardless of individual failures"
        )

    def test_network_exception_during_teardown_does_not_raise(
        self, minimal_config_file: Path
    ) -> None:
        """
        A network-level exception (e.g., ConnectionError) during DELETE is caught.

        This covers the case where the target server is unreachable during
        cleanup. The engine must catch the exception, log a WARNING, and
        continue — not propagate the exception out of _phase_6_teardown.
        """
        context = TestContext()
        context.register_resource_for_teardown("DELETE", "/api/v1/items/1")

        client = MagicMock()
        client.request.side_effect = ConnectionError("Server unreachable")

        engine = _build_engine(minimal_config_file)

        # Must not raise
        engine._phase_6_teardown(
            context=context,
            client=client,
            target=_mock_target(),
        )

    def test_network_exception_does_not_prevent_remaining_resources(
        self, minimal_config_file: Path
    ) -> None:
        """
        A network exception on one DELETE does not skip subsequent resources.

        Three resources registered; the first delete (LIFO last-in = /c) raises
        ConnectionError. The engine must still attempt /b and /a.
        """
        context = TestContext()
        for path in ["/a", "/b", "/c"]:
            context.register_resource_for_teardown("DELETE", path)

        call_log: list[str] = []

        def side_effect(**kwargs: object) -> tuple[MagicMock, MagicMock]:
            path = str(kwargs.get("path", ""))
            call_log.append(path)
            if path == "/c":
                raise ConnectionError("timeout")
            return (_stub_response(204), MagicMock())

        client = MagicMock()
        client.request.side_effect = side_effect

        engine = _build_engine(minimal_config_file)
        engine._phase_6_teardown(
            context=context,
            client=client,
            target=_mock_target(),
        )

        assert "/b" in call_log and "/a" in call_log, (
            "Resources after a network failure must still be attempted"
        )

    def test_teardown_failure_does_not_affect_context_state(
        self, minimal_config_file: Path
    ) -> None:
        """
        After teardown, registered_resource_count() is 0 even if deletes failed.

        drain_resources() is called at the start of teardown and clears the
        internal list regardless of whether the subsequent DELETE requests
        succeed. The registry must not retain references to resources that
        could not be deleted.
        """
        context = TestContext()
        context.register_resource_for_teardown("DELETE", "/api/v1/items/1")

        client = MagicMock()
        client.request.side_effect = ConnectionError("unreachable")

        engine = _build_engine(minimal_config_file)
        engine._phase_6_teardown(
            context=context,
            client=client,
            target=_mock_target(),
        )

        assert context.registered_resource_count() == 0, (
            "drain_resources() must clear the registry regardless of DELETE outcome"
        )
