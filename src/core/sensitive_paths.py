"""
src/core/sensitive_paths.py

The catalogue of sensitive paths: paths that frameworks and servers expose for
monitoring, debugging, documentation or configuration, which should not be
reachable unless intended (OWASP ASVS v5.0.0-13.4.2, 13.4.5).

One catalogue for every test that asks about them: 0.1 asks whether such a path exists outside the
specification (the suffixes go into the wordlist of ext.0.1.ffuf), 6.4 whether
it shows credentials. Each entry is a suffix without a leading slash, combined
with the base paths derived from the specification (the service prefixes, the
version directories), so that a service under /workshop gets
/workshop/actuator/env; and the documentation page that defines the path,
checked on 2026-10-21. A path only common by habit, with no defining source, is
not listed: the general API words come from the SecLists lists.

Dependency rule: imports only from the standard library.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SensitiveKind(StrEnum):
    """What a sensitive path exposes."""

    MONITORING = "MONITORING"
    """Health, metrics, internal state of the running application."""

    DEBUGGING = "DEBUGGING"
    """Debuggers, profilers, consoles, request traces, error logs."""

    DOCUMENTATION = "DOCUMENTATION"
    """API descriptions, their interactive pages, self-describing endpoints (GraphQL)."""

    CONFIGURATION = "CONFIGURATION"
    """Configuration and source-control files served by mistake."""


@dataclass(frozen=True)
class SensitivePath:
    """One sensitive path: its suffix, what it exposes, the page that defines it."""

    suffix: str
    kind: SensitiveKind
    source: str


_SPRING_ACTUATOR: str = "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html"
_GO_PPROF: str = "https://pkg.go.dev/net/http/pprof"
_WERKZEUG: str = "https://werkzeug.palletsprojects.com/en/stable/debug/"
_TELESCOPE: str = "https://laravel.com/docs/12.x/telescope"
_MOD_STATUS: str = "https://httpd.apache.org/docs/2.4/mod/mod_status.html"
_MOD_INFO: str = "https://httpd.apache.org/docs/2.4/mod/mod_info.html"
_GIT_LAYOUT: str = "https://git-scm.com/docs/gitrepository-layout"
_DOTENV: str = "https://github.com/motdotla/dotenv"
_FASTAPI: str = "https://fastapi.tiangolo.com/tutorial/metadata/"
_SPRINGDOC: str = "https://springdoc.org/"
_DJANGO_TOOLBAR: str = "https://django-debug-toolbar.readthedocs.io/en/latest/installation.html"
_SYMFONY_PROFILER: str = "https://symfony.com/doc/current/profiler.html"
_RAILS_ROUTING: str = "https://guides.rubyonrails.org/routing.html"
_PROMETHEUS: str = "https://prometheus.io/docs/guides/node-exporter/"
_GRAPHQL_HTTP: str = "https://graphql.github.io/graphql-over-http/draft/"
_ASPNET_TRACE: str = "https://learn.microsoft.com/en-us/previous-versions/aspnet/wwh16c6c(v=vs.100)"
_ELMAH: str = "https://elmah.github.io/a/securing-error-log-pages/"
_KUBERNETES_HEALTH: str = "https://kubernetes.io/docs/reference/using-api/health-checks/"

_M = SensitiveKind.MONITORING
_D = SensitiveKind.DEBUGGING
_DOC = SensitiveKind.DOCUMENTATION
_C = SensitiveKind.CONFIGURATION

SENSITIVE_PATHS: tuple[SensitivePath, ...] = (
    # Spring Boot Actuator: the endpoints that expose state or act on the application.
    SensitivePath("actuator", _M, _SPRING_ACTUATOR),
    SensitivePath("actuator/health", _M, _SPRING_ACTUATOR),
    SensitivePath("actuator/info", _M, _SPRING_ACTUATOR),
    SensitivePath("actuator/metrics", _M, _SPRING_ACTUATOR),
    SensitivePath("actuator/prometheus", _M, _SPRING_ACTUATOR),
    SensitivePath("actuator/env", _C, _SPRING_ACTUATOR),
    SensitivePath("actuator/configprops", _C, _SPRING_ACTUATOR),
    SensitivePath("actuator/beans", _D, _SPRING_ACTUATOR),
    SensitivePath("actuator/mappings", _D, _SPRING_ACTUATOR),
    SensitivePath("actuator/loggers", _D, _SPRING_ACTUATOR),
    SensitivePath("actuator/logfile", _D, _SPRING_ACTUATOR),
    SensitivePath("actuator/httpexchanges", _D, _SPRING_ACTUATOR),
    SensitivePath("actuator/threaddump", _D, _SPRING_ACTUATOR),
    SensitivePath("actuator/heapdump", _D, _SPRING_ACTUATOR),
    SensitivePath("actuator/shutdown", _D, _SPRING_ACTUATOR),
    # Profilers, debuggers, consoles, error logs.
    SensitivePath("debug/pprof/", _D, _GO_PPROF),
    SensitivePath("console", _D, _WERKZEUG),
    SensitivePath("telescope", _D, _TELESCOPE),
    SensitivePath("__debug__/", _D, _DJANGO_TOOLBAR),
    SensitivePath("_profiler", _D, _SYMFONY_PROFILER),
    SensitivePath("rails/info/routes", _D, _RAILS_ROUTING),
    SensitivePath("trace.axd", _D, _ASPNET_TRACE),
    SensitivePath("elmah.axd", _D, _ELMAH),
    # Web server status pages.
    SensitivePath("server-status", _M, _MOD_STATUS),
    SensitivePath("server-info", _C, _MOD_INFO),
    SensitivePath("metrics", _M, _PROMETHEUS),
    # Health endpoints: defined by Kubernetes for its API server (healthz deprecated
    # since v1.16), the convention applications follow.
    SensitivePath("healthz", _M, _KUBERNETES_HEALTH),
    SensitivePath("livez", _M, _KUBERNETES_HEALTH),
    SensitivePath("readyz", _M, _KUBERNETES_HEALTH),
    # API descriptions and their pages.
    SensitivePath("openapi.json", _DOC, _FASTAPI),
    SensitivePath("docs", _DOC, _FASTAPI),
    SensitivePath("redoc", _DOC, _FASTAPI),
    SensitivePath("v3/api-docs", _DOC, _SPRINGDOC),
    SensitivePath("swagger-ui.html", _DOC, _SPRINGDOC),
    SensitivePath("graphql", _DOC, _GRAPHQL_HTTP),
    # Files served by mistake.
    SensitivePath(".env", _C, _DOTENV),
    SensitivePath(".git/config", _C, _GIT_LAYOUT),
    SensitivePath(".git/HEAD", _C, _GIT_LAYOUT),
)
