"""
src/test_config/runtime.py

RuntimeTestsConfig: the per-test parameters as the tests receive them.

One field per native test (a model for every test, possibly empty), named
``test_<D>_<N>``.
Each field holds the same model that validates ``config.yaml``
(``tests.domain_<D>.test_<D>_<N>``): there is a single definition of every
parameter. The engine builds this container in Phase 3 with
``RuntimeTestsConfig.from_domains(config.tests)``, which collects the validated
models by name (no copy, no hand-written wiring), stores it in
``TargetContext.tests_config``, and tests read
``target.tests_config.test_<D>_<N>.<param>``.

All models are frozen, so the container and its content are immutable.

Dependency rule: imports only from pydantic, the stdlib and the domain
modules of this package.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from src.test_config.domain_0 import Test01Config, Test02ProbeConfig, Test03Config
from src.test_config.domain_1 import Test11Config, Test14Config, Test15Config, Test16Config
from src.test_config.domain_2 import Test21Config
from src.test_config.domain_3 import Test33Config
from src.test_config.domain_4 import Test41ProbeConfig, Test42AuditConfig, Test43AuditConfig
from src.test_config.domain_6 import Test62AuditConfig, Test64AuditConfig
from src.test_config.domain_7 import Test72SSRFConfig


class RuntimeTestsConfig(BaseModel):
    """
    Immutable container of the per-test parameters, one field per test.

    Populated by engine.py in Phase 3 from config.tests (the validated models
    themselves) and stored in TargetContext.tests_config. The defaults of every
    field are the defaults of the corresponding model, so an empty container
    equals a configuration without a ``tests:`` section.
    """

    # extra="forbid": a test model present in a domain but not declared here
    # stops from_domains() instead of being silently dropped.
    model_config = {"frozen": True, "extra": "forbid"}

    test_0_1: Test01Config = Field(
        default_factory=Test01Config,
        description="Test 0.1 (Shadow API Discovery): config.tests.domain_0.test_0_1.",
    )
    test_0_2: Test02ProbeConfig = Field(
        default_factory=Test02ProbeConfig,
        description="Test 0.2 (Gateway Deny-by-Default): config.tests.domain_0.test_0_2.",
    )
    test_0_3: Test03Config = Field(
        default_factory=Test03Config,
        description="Test 0.3 (Deprecated API Enforcement): no parameters.",
    )
    test_1_1: Test11Config = Field(
        default_factory=Test11Config,
        description="Test 1.1 (Authentication Required): config.tests.domain_1.test_1_1.",
    )
    test_1_4: Test14Config = Field(
        default_factory=Test14Config,
        description="Test 1.4 (Token Revocation): config.tests.domain_1.test_1_4.",
    )
    test_1_5: Test15Config = Field(
        default_factory=Test15Config,
        description="Test 1.5 (Insecure Credential Transport): config.tests.domain_1.test_1_5.",
    )
    test_1_6: Test16Config = Field(
        default_factory=Test16Config,
        description="Test 1.6 (Secure Session Management): config.tests.domain_1.test_1_6.",
    )
    test_2_1: Test21Config = Field(
        default_factory=Test21Config,
        description="Test 2.1 (RBAC Enforcement): config.tests.domain_2.test_2_1.",
    )
    test_3_3: Test33Config = Field(
        default_factory=Test33Config,
        description="Test 3.3 (HMAC Configuration Audit): config.tests.domain_3.test_3_3.",
    )
    test_4_1: Test41ProbeConfig = Field(
        default_factory=Test41ProbeConfig,
        description="Test 4.1 (Rate Limiting): config.tests.domain_4.test_4_1.",
    )
    test_4_2: Test42AuditConfig = Field(
        default_factory=Test42AuditConfig,
        description="Test 4.2 (Timeout Configuration Audit): config.tests.domain_4.test_4_2.",
    )
    test_4_3: Test43AuditConfig = Field(
        default_factory=Test43AuditConfig,
        description="Test 4.3 (Circuit Breaker Audit): config.tests.domain_4.test_4_3.",
    )
    test_6_2: Test62AuditConfig = Field(
        default_factory=Test62AuditConfig,
        description="Test 6.2 (Security Headers Audit): config.tests.domain_6.test_6_2.",
    )
    test_6_4: Test64AuditConfig = Field(
        default_factory=Test64AuditConfig,
        description="Test 6.4 (Hardcoded Credentials Audit): config.tests.domain_6.test_6_4.",
    )
    test_7_2: Test72SSRFConfig = Field(
        default_factory=Test72SSRFConfig,
        description="Test 7.2 (SSRF Prevention): config.tests.domain_7.test_7_2.",
    )

    @classmethod
    def from_domains(cls, tests: BaseModel) -> RuntimeTestsConfig:
        """
        Build the container from the per-domain containers of ``config.tests``.

        Every field of every domain container (``domain_<D>`` →
        ``test_<D>_<N>``) is collected by name and passed as it is, so the
        tests receive the same validated, frozen model objects.

        Two mismatches stop the run instead of silently using defaults:
            - a domain declares a test that this class does not
              (rejected by ``extra="forbid"``, Pydantic ``ValidationError``);
            - this class declares a test that no domain provides
              (``ValueError`` naming the missing tests).

        Args:
            tests: The validated ``config.tests`` model (``TestsConfig``),
                   typed as ``BaseModel`` so that this package does not
                   import from ``src/config/``.

        Returns:
            The populated, frozen RuntimeTestsConfig.

        Raises:
            ValueError: If a declared test has no model in any domain.
            pydantic.ValidationError: If a domain declares an unknown test.
        """
        collected: dict[str, BaseModel] = {}
        for domain_name in type(tests).model_fields:
            domain: BaseModel = getattr(tests, domain_name)
            for test_name in type(domain).model_fields:
                collected[test_name] = getattr(domain, test_name)

        missing = sorted(set(cls.model_fields) - set(collected))
        if missing:
            raise ValueError(
                "RuntimeTestsConfig declares tests that no domain container provides: "
                f"{missing}. Add the model to src/test_config/domain_<D>.py and its field "
                "to TestDomain<D>Config."
            )
        return cls.model_validate(collected)
