"""
src/test_config/

Per-test configuration models: one Pydantic v2 model per native test
(``Test<XY>Config``, empty when the test has no parameters), grouped by domain
(``domain_<D>.py``, with a ``TestDomain<D>Config`` container per domain).

These models are the single definition of every test parameter. They are used
both to validate the ``tests:`` section of ``config.yaml`` (``src/config/``)
and, unchanged, by the tests at runtime through ``TargetContext.tests_config``.

Dependency rule: this package is the lowest layer of the tool. It imports only
from pydantic and the standard library, never from another ``src/`` package.
``config/`` imports it to validate the configuration; ``core/`` imports it only
to type ``TargetContext.tests_config``; tests import it to type their
parameters. The rule is checked by ``lint-imports`` (``hatch run dev:check``).
"""
