"""
src/__init__.py

Package-level metadata for APIGuard Assurance.

The single source of truth for the tool version is the ``version`` field in
``pyproject.toml``.  This module exposes ``__version__`` by reading the
installed package metadata at runtime via ``importlib.metadata.version()``.

Importers (e.g. ``src.cli``, ``src.report.builder``) read ``__version__``
from here rather than hardcoding a string, eliminating drift between
``pyproject.toml`` and the in-code constant.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version("apiguard-assurance")
except PackageNotFoundError:
    # Fallback for development environments where the package is not yet
    # installed (e.g. ``python -m src.cli`` from a fresh checkout without
    # ``pip install -e .``).  The canonical value lives in pyproject.toml.
    __version__ = "0.0.0+unknown"
