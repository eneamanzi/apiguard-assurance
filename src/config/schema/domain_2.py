"""
src/config/schema/domain_2.py

Pydantic v2 configuration models for Domain 2 (Authorization) tests.

Tests covered: 2.1.

Adding a new Domain 2 test requires:
    1. Defining a Test2XConfig model in this file.
    2. Adding a field to TestDomain2Config below.
    3. Adding a RuntimeTest2XConfig mirror in core/models/runtime.py.
    4. Populating it in engine.py Phase 3.
    5. Adding the tests.domain_2.test_2_X block to config.yaml.

Dependency rule: imports only from pydantic and the stdlib.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Constants — Test 2.1
# ---------------------------------------------------------------------------

# Default list of admin-only endpoints to probe with a non-privileged token.
# OWASP ASVS v5.0.0 V8.3.1: all privileged endpoints must enforce role checks.
# These defaults are Forgejo-specific; operators should extend this list to
# cover all admin-only endpoints documented in their target's OpenAPI spec.
TEST_21_ADMIN_ENDPOINT_PATHS_DEFAULT: list[str] = ["/api/v1/admin/users"]

# Default HTTP method for the admin endpoint probe.
TEST_21_ADMIN_ENDPOINT_METHOD_DEFAULT: str = "GET"

# ---------------------------------------------------------------------------
# Per-test configs
# ---------------------------------------------------------------------------


class Test21Config(BaseModel):
    """
    Tuning parameters for Test 2.1 (Only Authorized Users Access Privileged Endpoints).

    The test probes each path in admin_endpoint_paths using a non-privileged
    ROLE_USER_A token and expects 403 Forbidden.  A 2xx response indicates
    broken function-level authorization (OWASP API5:2023, BFLA).

    References: OWASP API5:2023, OWASP ASVS v5.0.0 V8.3.1+V8.2.2,
    NIST SP 800-53 Rev.5 AC-3.
    """

    model_config = {"frozen": True}

    admin_endpoint_paths: Annotated[
        list[str],
        Field(min_length=1),
    ] = Field(
        default_factory=lambda: list(TEST_21_ADMIN_ENDPOINT_PATHS_DEFAULT),
        description=(
            "List of admin-only endpoint paths to probe with a non-privileged token.  "
            "Each path must start with '/'.  "
            "At least one path is required.  "
            "Default: ['/api/v1/admin/users'] (Forgejo admin user-list endpoint)."
        ),
    )
    admin_endpoint_method: str = Field(
        default=TEST_21_ADMIN_ENDPOINT_METHOD_DEFAULT,
        description=(
            "HTTP method to use when probing each admin endpoint.  "
            f"Default: '{TEST_21_ADMIN_ENDPOINT_METHOD_DEFAULT}'."
        ),
    )


# ---------------------------------------------------------------------------
# Domain-level aggregator
# ---------------------------------------------------------------------------


class TestDomain2Config(BaseModel):
    """
    Aggregator for all Domain 2 (Authorization) test configs.

    One field per test in the domain. tests_config.py imports only this class.
    Adding a new Domain 2 test requires:
        1. Defining a Test2XConfig model above.
        2. Adding a field here.
        3. Adding the corresponding RuntimeTest2XConfig in core/models/runtime.py.
        4. Populating it in engine.py Phase 3.
    """

    model_config = {"frozen": True}

    test_2_1: Test21Config = Field(
        default_factory=Test21Config,
        description=(
            "Tuning parameters for Test 2.1 "
            "(Only Authorized Users Access Privileged Endpoints). "
            "Maps to 'tests.domain_2.test_2_1' in config.yaml."
        ),
    )
