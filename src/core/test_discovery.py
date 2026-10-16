"""
src/core/test_discovery.py

Find every test class of a package, or stop the run saying why one is missing.

Shared by the native registry (src/tests/, modules test_*.py, BaseTest) and
the external registry (src/external_tests/, modules ext_test_*.py,
ExternalToolTest). A test that is silently left out reads, in a security
report, as a guarantee that holds: so every reason a test module or class
cannot be used is collected as a problem, and discovery raises one
TestDefinitionError listing them all [BLOCKS STARTUP]:

    - a test module that cannot be imported (syntax error, missing import,
      an invalid ``info = TestInfo(...)`` declaration, any exception);
    - a test module that is not in a package (its folder has no
      __init__.py), which the package scan would never see;
    - a test class without ``info``, or whose ``info`` is of the other kind
      (an external ID on a native class or the opposite);
    - a test ID used by two classes;
    - a test class that cannot be instantiated without arguments.

A class whose name starts with "_" is a helper base shared by the tests of
its module, not a test; abstract classes and classes imported from another
module are not tests of the module either.

Dependency rule: imports only from the standard library, pydantic, structlog
and src.core. The packages to scan are named by the caller (imported by
name at run time), so core never imports tests.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import types
from pathlib import Path
from typing import TypeGuard, TypeVar

import structlog
from pydantic import ValidationError

from src.core.assessment_test import AssessmentTest
from src.core.exceptions import raise_for_test_definition_problems
from src.core.test_metadata import PRIVATE_CLASS_PREFIX, TestInfo, info_problems

log: structlog.BoundLogger = structlog.get_logger(__name__)

_TestT = TypeVar("_TestT", bound=AssessmentTest)

# Suffix of a Python module file.
_MODULE_SUFFIX: str = ".py"


def discover_tests(
    package: str,
    module_prefix: str,
    base: type[_TestT],
    *,
    external: bool,
) -> list[_TestT]:
    """
    Import every test module of a package and instantiate its test classes.

    Args:
        package:       Dotted name of the package to scan (e.g. "src.tests").
        module_prefix: Prefix of the test module names (e.g. "test_").
        base:          Base class of the tests (BaseTest or ExternalToolTest).
        external:      True when the tests are external (IDs "ext.X.Y.tool").

    Returns:
        One instance per test class, in module and class order.

    Raises:
        TestDefinitionError: Listing every problem found, when there is any.
    """
    problems: list[str] = []
    modules = _import_test_modules(package, module_prefix, problems)
    instances: list[_TestT] = []
    owner_by_id: dict[str, str] = {}
    for module in modules:
        for class_name, cls in inspect.getmembers(module, inspect.isclass):
            if not _is_test_class(cls, class_name, module.__name__, base):
                continue
            where = f"{class_name} ({module.__name__})"
            info = cls.__dict__.get("info")
            if not isinstance(info, TestInfo):
                problems.append(f"{where}: declare 'info = TestInfo(...)' in the class")
                continue
            if info.is_external != external:
                kind = "an external test ('ext.X.Y.tool')" if external else "a native test ('X.Y')"
                problems.append(f"{where}: id {info.id!r} is not the ID of {kind}")
                continue
            if info.id in owner_by_id:
                problems.append(f"{where}: id {info.id!r} already used by {owner_by_id[info.id]}")
                continue
            owner_by_id[info.id] = where
            try:
                instance = cls()
            except Exception as exc:  # noqa: BLE001 -- any failure is reported
                problems.append(
                    f"{where}: cannot be instantiated without arguments "
                    f"({type(exc).__name__}: {exc})"
                )
                continue
            instances.append(instance)
            log.debug("test_discovered", test_id=info.id, class_name=class_name)
    raise_for_test_definition_problems(problems)
    return instances


def _import_test_modules(
    package: str,
    module_prefix: str,
    problems: list[str],
) -> list[types.ModuleType]:
    """
    Import the test modules of a package, collecting why one cannot be used.

    Args:
        package:       Dotted name of the package to scan.
        module_prefix: Prefix of the test module names.
        problems:      Receives one message per module that cannot be used.

    Returns:
        The imported test modules.
    """
    try:
        root = importlib.import_module(package)
    except Exception as exc:  # noqa: BLE001 -- any failure is reported
        problems.append(f"{package}: cannot be imported ({type(exc).__name__}: {exc})")
        return []
    root_paths = [Path(p) for p in getattr(root, "__path__", [])]

    def on_walk_error(name: str) -> None:
        problems.append(f"{name}: the package cannot be scanned")

    modules: list[types.ModuleType] = []
    seen_files: set[Path] = set()
    for module_info in pkgutil.walk_packages(
        path=[str(p) for p in root_paths], prefix=f"{package}.", onerror=on_walk_error
    ):
        short_name = module_info.name.rsplit(".", 1)[-1]
        if not short_name.startswith(module_prefix):
            continue
        # Seen by the scan whether or not it imports (the disk check below).
        finder_path = getattr(module_info.module_finder, "path", None)
        if finder_path is not None:
            seen_files.add((Path(finder_path) / f"{short_name}{_MODULE_SUFFIX}").resolve())
        try:
            module = importlib.import_module(module_info.name)
        except ValidationError as exc:
            problems.extend(f"{module_info.name}: {p}" for p in info_problems(exc))
            continue
        except Exception as exc:  # noqa: BLE001 -- any failure is reported
            problems.append(f"{module_info.name}: cannot be imported ({type(exc).__name__}: {exc})")
            continue
        modules.append(module)

    # A test module in a folder without __init__.py is not in the package:
    # the scan above never sees it, so it is looked for on disk.
    for root_path in root_paths:
        # Paths are shown from the folder holding the top-level package ("src/...").
        shown_from = root_path.parents[package.count(".")]
        for file in sorted(root_path.rglob(f"{module_prefix}*{_MODULE_SUFFIX}")):
            if file.resolve() not in seen_files:
                problems.append(
                    f"{file.relative_to(shown_from)}: not in a package, so never loaded: "
                    f"add an __init__.py to {file.parent.relative_to(shown_from)}"
                )
    return modules


def _is_test_class(
    cls: type, class_name: str, module_name: str, base: type[_TestT]
) -> TypeGuard[type[_TestT]]:
    """
    True for a concrete test class defined in the module.

    Args:
        cls:         A class found in the module.
        class_name:  Its name in the module.
        module_name: The module's dotted name.
        base:        Base class of the tests.

    Returns:
        False for the base itself, a helper base ("_" prefix), an abstract
        class or a class imported from another module.
    """
    return (
        issubclass(cls, base)
        and cls is not base
        and not class_name.startswith(PRIVATE_CLASS_PREFIX)
        and cls.__module__ == module_name
        and not inspect.isabstract(cls)
    )
