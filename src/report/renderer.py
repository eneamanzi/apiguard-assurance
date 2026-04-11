"""
src/report/renderer.py

HTML report renderer: transforms a ReportData object into a self-contained
HTML file using Jinja2 template rendering.

This module is responsible exclusively for:
    1. Locating and loading the Jinja2 template from the templates/ directory.
    2. Registering custom Jinja2 filters for display formatting.
    3. Rendering the template with the ReportData as context.
    4. Writing the rendered HTML to the specified output path.

What this module does NOT do:
    - Compute statistics or aggregate data (builder.py's responsibility).
    - Define the visual structure beyond what the template declares.
    - Validate the ReportData (already validated by Pydantic in builder.py).

The rendered HTML is a single self-contained file: all CSS and JavaScript
are inlined in the template. No external CDN or asset file is required.
This ensures the report is readable offline and can be attached to the
thesis or delivered as a standalone artifact.

Dependency rule:
    This module imports from stdlib, jinja2, structlog, pathlib, and
    src.report.builder only. It must never import from engine.py, tests/,
    discovery/, config/, or core/.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from src.report.builder import ReportData

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Absolute path to the templates directory, relative to this file's location.
# Using Path(__file__).parent ensures the path is correct regardless of the
# working directory from which the tool is invoked.
_TEMPLATES_DIR: Path = Path(__file__).parent / "templates"

# Name of the main report template file inside _TEMPLATES_DIR.
_REPORT_TEMPLATE_NAME: str = "report.html"


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def render_html_report(
    report_data: ReportData,
    output_path: Path,
) -> None:
    r"""
    Render the assessment report as a self-contained HTML file.

    Loads the Jinja2 template from src/report/templates/report.html,
    renders it with report_data as the template context, and writes the
    result to output_path.

    The output directory is created if it does not exist. An existing file
    at output_path is overwritten without warning: each pipeline run produces
    a fresh report, and the run_id in the report header distinguishes runs.

    The context includes a ``report_json`` key: a pre-serialised JSON string
    of the complete ReportData (mode="json"), safe for embedding inside an
    HTML ``<script type="application/json">`` block.  The string has all
    ``</`` sequences replaced with ``<\/`` (valid JSON, prevents the browser
    from interpreting the closing tag and triggering premature script-block
    termination).

    Args:
        report_data: Frozen ReportData from builder.build_report_data().
        output_path: Filesystem path for the output HTML file.
                     Typically Path("assessment_report.html") in the
                     working directory, as set by engine.REPORT_OUTPUT_PATH.

    Raises:
        OSError: If the output file cannot be written (permission denied,
                 filesystem full). Not wrapped: the engine logs this error
                 and continues — a missing report does not change the exit code.
        jinja2.TemplateNotFound: If report.html is missing from the templates
                                  directory. This is a packaging error, not a
                                  runtime error.
        jinja2.TemplateSyntaxError: If the template contains a Jinja2 syntax
                                     error. This is a development-time error.
    """
    log.debug(
        "renderer_loading_template",
        template_dir=str(_TEMPLATES_DIR),
        template_name=_REPORT_TEMPLATE_NAME,
    )

    env = _build_jinja2_environment()
    template = env.get_template(_REPORT_TEMPLATE_NAME)

    # Render with the ReportData model's dict representation.
    # model_dump() produces a plain dict that Jinja2 can traverse without
    # needing to understand Pydantic models. mode="python" preserves Python
    # types (datetime objects, enums) rather than converting to JSON strings,
    # giving the template access to rich objects where needed.
    context = report_data.model_dump(mode="python")

    # Also expose the original ReportData object for template code that
    # benefits from Pydantic's property methods (e.g., domain.has_failures).
    context["report"] = report_data

    # Pre-serialise a JSON-safe string for JavaScript embedding.
    # The template embeds this inside a <script type="application/json"> block
    # so that the interactive report (filters, copy, export) can operate on
    # the full dataset without any additional network round-trips.
    # _safe_json_dumps ensures the string will not prematurely close the block.
    context["report_json"] = _safe_json_dumps(report_data.model_dump(mode="json"))

    rendered_html = template.render(**context)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered_html, encoding="utf-8")

    log.info(
        "renderer_html_report_written",
        output_path=str(output_path),
        size_bytes=len(rendered_html.encode("utf-8")),
    )


# ---------------------------------------------------------------------------
# Jinja2 environment setup
# ---------------------------------------------------------------------------


def _build_jinja2_environment() -> Environment:
    """
    Build and configure the Jinja2 Environment for report rendering.

    Configuration choices:
        - FileSystemLoader: loads templates from the templates/ directory.
        - StrictUndefined: raises UndefinedError for any undefined variable
          in the template, preventing silent empty-string substitutions that
          would produce a malformed report without any visible error.
        - autoescape on HTML: prevents XSS if report data contains angle
          brackets (e.g., in a Finding.detail that documents an injection
          payload). All string interpolations in the template are escaped.
        - Custom filters: registered for display formatting (see below).

    Returns:
        Configured Jinja2 Environment.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Register custom filters.
    env.filters["status_badge_class"] = _filter_status_badge_class
    env.filters["duration_display"] = _filter_duration_display
    env.filters["default_dash"] = _filter_default_dash

    return env


# ---------------------------------------------------------------------------
# Custom Jinja2 filters
# ---------------------------------------------------------------------------


def _filter_status_badge_class(status: str) -> str:
    """
    Map a TestStatus value string to a CSS badge class name.

    Used in the template as: {{ row.status | status_badge_class }}
    Produces class names that the inline CSS in the template styles.

    Args:
        status: Status value string: 'PASS', 'FAIL', 'SKIP', or 'ERROR'.

    Returns:
        CSS class string for the status badge element.
    """
    mapping: dict[str, str] = {
        "PASS": "badge-pass",
        "FAIL": "badge-fail",
        "SKIP": "badge-skip",
        "ERROR": "badge-error",
    }
    return mapping.get(status.upper(), "badge-unknown")


def _filter_duration_display(duration_ms: float | None) -> str:
    """
    Format an optional duration_ms float into a human-readable string.

    Used in the template as: {{ row.duration_ms | duration_display }}

    Args:
        duration_ms: Duration in milliseconds, or None if not measured.

    Returns:
        Formatted string: '1234.5 ms', '< 1 ms', or '—' for None.
    """
    if duration_ms is None:
        return "\u2014"
    if duration_ms < 1.0:
        return "< 1 ms"
    if duration_ms >= 1000.0:
        seconds = duration_ms / 1000.0
        return f"{seconds:.1f} s"
    return f"{duration_ms:.1f} ms"


def _filter_default_dash(value: object) -> str:
    """
    Return the string value or an em dash if falsy.

    Used in the template as: {{ row.cwe_id | default_dash }}

    Args:
        value: Any value. Falsy values (None, '', [], 0) return em dash.

    Returns:
        str representation of value, or '—' if falsy.
    """
    if not value:
        return "\u2014"
    return str(value)


# ---------------------------------------------------------------------------
# Internal serialisation helpers
# ---------------------------------------------------------------------------


def _safe_json_dumps(data: Any) -> str:  # noqa: ANN401
    """
    Serialise *data* to a JSON string that is safe for embedding inside an
    HTML ``<script>`` block.

    The standard :func:`json.dumps` does not escape forward slashes, so a
    string value containing ``</script>`` inside the JSON would prematurely
    terminate the enclosing script element in the browser's HTML parser.

    This function applies the standard mitigation: all occurrences of ``</``
    are replaced with ``<\\/`` (the JSON-legal escape for the forward slash),
    which the browser's HTML parser will not interpret as a closing tag while
    the JavaScript ``JSON.parse`` will decode correctly.

    ``datetime`` objects and other non-JSON-serialisable values are converted
    to their ISO string representation via the ``default=str`` fallback.

    Args:
        data: Any JSON-serialisable value produced by
              ``ReportData.model_dump(mode="json")``.

    Returns:
        JSON string safe for ``{{ report_json | safe }}`` in an HTML template.
    """
    raw: str = json.dumps(data, default=str, ensure_ascii=False)
    # Replace '</' with '<\/' to prevent </script> injection.
    # This is a well-established technique for safely embedding JSON in HTML.
    return raw.replace("</", r"<\/")
