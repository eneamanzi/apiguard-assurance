"""
src/tests/strategy.py

Convenience re-export of TestStrategy for test module authors.

The canonical definition of TestStrategy lives in src/core/models.py,
where it is co-located with the other shared domain types (TestStatus,
TestResult, Finding). It is defined there — rather than here — because
it is consumed by multiple layers: TargetContext (core/context.py),
ToolConfig (config/schema.py), TestRegistry (tests/registry.py), and
the engine. Defining it in tests/ would require those layers to import
from tests/, violating the unidirectional dependency rule.

This module exists so that test authors can write:

    from src.tests.strategy import TestStrategy

instead of:

    from src.core.models import TestStrategy

Both imports resolve to the identical class. This file must never define
any new symbols — it only re-exports.
"""

from src.core.models import TestStrategy

__all__ = ["TestStrategy"]
