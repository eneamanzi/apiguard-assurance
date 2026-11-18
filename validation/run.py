"""
validation/run.py

Produce the cases of the case files on the labs and compare each with what the
code recorded (README.md).

For each group of cases sharing a lab, a variant and a tool configuration:
record the lab's state, apply the variant, run only the tests of those cases,
read the cases each test recorded (sub_tests[].cases of the report), undo the
variant and check the lab is back to the recorded state; the run stops when it
is not. The result is written to validation/results/, readable (Markdown) and
for counting (JSON), naming the commit and whether the working tree had changes.

Usage: python validation/run.py [--test ID ...] [--lab LAB]
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import ssl
import subprocess  # noqa: S404 -- the runner drives docker, git and the tool
import sys
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import yaml
from catalogue import (
    AS_BUILT,
    LABS,
    ROOT,
    CaseEntry,
    Change,
    SpecEdit,
    declared_cases,
    load_case_file,
    load_variants,
)
from dotenv import load_dotenv
from rich.console import Console
from src import __version__
from src.core.models import SubTestResult, TestStatus, combine_sub_tests

console = Console()
LAB_DIR: Path = ROOT / "test-environments"
RESULTS_DIR: Path = Path(__file__).resolve().parent / "results"
ENV_FILE: Path = ROOT / ".env"
# The gateway container service of each lab, recreated after a change to its file.
_KONG_SERVICE: str = "kong"
# The full reset of a lab (docs/project/maintainer-commands.md, "Full reset"):
# the gateway service started first, then the setup services, in order.
_RESET: dict[str, tuple[str, tuple[str, ...]]] = {
    "forgejo-kong": ("kong", ("forgejo-setup",)),
    "crapi-kong": ("kong", ("crapi-setup",)),
    "forgejo-apisix": ("apisix", ("forgejo-setup", "apisix-setup")),
}
_COMPOSE_FILE: str = "docker-compose.yml"
_APISIX_SETUP_SERVICE: str = "apisix-setup"
_APISIX_ADMIN_KEY_VAR: str = "APISIX_ADMIN_KEY"
# What the Admin APIs are read for, to compare a lab's state before and after.
_KONG_COLLECTIONS: tuple[str, ...] = ("services", "routes", "plugins", "consumers", "upstreams")
_APISIX_COLLECTIONS: tuple[str, ...] = (
    "routes",
    "services",
    "upstreams",
    "global_rules",
    "plugin_configs",
    "consumers",
    "plugin_metadata",
)
# Fields that change on every load and say nothing about the configuration.
_VOLATILE: frozenset[str] = frozenset({"created_at", "updated_at", "create_time", "update_time"})
_HTTP_TIMEOUT: float = 10.0
_OK: str = "OK"
_DIFFERENT: str = "DIFFERENT"


@dataclass
class Group:
    """Cases produced by one run: same lab, variant, configuration and specification."""

    lab: str
    variant: str
    config: dict[str, object]
    spec: SpecEdit | None
    cases: list[tuple[str, CaseEntry]] = field(default_factory=list)

    @property
    def tests(self) -> list[str]:
        """The tests to run, in the order of their cases."""
        return list(dict.fromkeys(test for test, _ in self.cases))


# ---------------------------------------------------------------------------
# Labs: configuration, state, changes
# ---------------------------------------------------------------------------


def lab_config(lab: str) -> dict[str, Any]:
    """The tool configuration of a lab, as committed."""
    loaded: dict[str, Any] = yaml.safe_load(
        (LAB_DIR / lab / "config.yaml").read_text(encoding="utf-8")
    )
    return loaded


def _expand(value: str) -> str:
    """A configuration value with its ${VAR} read from the environment."""
    return os.path.expandvars(value)


def _admin_client(lab: str) -> tuple[httpx.Client, str]:
    """An HTTP client for the lab's Admin API as its configuration reaches it, and the base URL."""
    admin = lab_config(lab)["gateway"]["admin"]
    tls = admin.get("tls") or {}
    context = ssl.create_default_context(
        cafile=str(ROOT / tls["ca_bundle"]) if tls.get("ca_bundle") else None
    )
    if tls.get("client_cert"):
        context.load_cert_chain(str(ROOT / tls["client_cert"]), str(ROOT / tls["client_key"]))
    headers = {k: _expand(str(v)) for k, v in (admin.get("headers") or {}).items()}
    client = httpx.Client(verify=context, headers=headers, timeout=_HTTP_TIMEOUT)
    url = str(admin["url"]).rstrip("/")
    if lab_config(lab)["gateway"]["adapter"] == "apisix" and not url.endswith("/apisix/admin"):
        url += "/apisix/admin"
    return client, url


def _strip(value: object) -> object:
    """A JSON value without the fields that change on every load."""
    if isinstance(value, dict):
        return {k: _strip(v) for k, v in sorted(value.items()) if k not in _VOLATILE}
    if isinstance(value, list):
        return [_strip(v) for v in value]
    return value


def lab_state(lab: str) -> dict[str, Any]:
    """What the lab's gateway is configured with, read from its Admin API, for comparison."""
    client, url = _admin_client(lab)
    state: dict[str, Any] = {}
    with client:
        if lab_config(lab)["gateway"]["adapter"] == "kong":
            for name in _KONG_COLLECTIONS:
                state[name] = _strip(client.get(f"{url}/{name}").json().get("data"))
        else:
            for name in _APISIX_COLLECTIONS:
                body = client.get(f"{url}/{name}").json()
                entries = sorted(body["list"], key=lambda e: str(e.get("key")))
                state[name] = [[e.get("key"), _strip(e.get("value"))] for e in entries]
    state["kong.yml"] = _kong_file(lab).read_text(encoding="utf-8") if _is_kong(lab) else None
    return state


def _is_kong(lab: str) -> bool:
    """Whether the lab's gateway is Kong."""
    return bool(lab_config(lab)["gateway"]["adapter"] == "kong")


def _kong_file(lab: str) -> Path:
    """The declarative file of a Kong lab."""
    return LAB_DIR / lab / "kong" / "kong.yml"


def _compose(lab: str, *args: str) -> None:
    """Run docker compose in the lab's folder; raise when it fails."""
    command = ["docker", "compose", "--env-file", str(ENV_FILE), *args]
    subprocess.run(command, cwd=LAB_DIR / lab, check=True, capture_output=True)  # noqa: S603


def _kong_target(data: dict[str, Any], change: Change) -> dict[str, Any]:
    """The service or route of kong.yml a change names."""
    fields = change.model_extra or {}
    for service in data.get("services") or []:
        if service.get("name") == fields.get("service"):
            found: dict[str, Any] = service
            return found
        for route in service.get("routes") or []:
            if route.get("name") == fields.get("route"):
                hit: dict[str, Any] = route
                return hit
    raise ValueError(f"kong.yml has no service or route named in {fields}")


def _apply_kong(data: dict[str, Any], change: Change) -> None:
    """Apply one Kong change to the parsed kong.yml."""
    fields = change.model_extra or {}
    if change.kind == "kong_entity_add":
        data.setdefault(fields["list"], []).append(fields["item"])
        return
    if change.kind == "kong_entity_set":
        for entity in data.get(fields["list"]) or []:
            if entity.get("name") == fields["name"]:
                entity.update(fields["set"])
                return
        raise ValueError(f"kong.yml has no {fields['list']} named {fields['name']!r}")
    if change.kind == "kong_plugin_add":
        holder = data if fields.get("global") else _kong_target(data, change)
        holder.setdefault("plugins", []).append(fields["plugin"])
        return
    target = _kong_target(data, change)
    for plugin in target.get("plugins") or []:
        if plugin.get("name") == fields["plugin"]:
            plugin.setdefault("config", {}).update(fields["set"])
            return
    raise ValueError(f"no plugin {fields['plugin']!r} on {fields}")


@contextmanager
def applied(lab: str, variant: str) -> Iterator[None]:
    """Apply a lab's variant for the duration of the block, undo it, check the state is back."""
    if variant == AS_BUILT:
        yield
        return
    changes = load_variants(lab)[variant].changes
    before = lab_state(lab)
    stopped: list[str] = []
    recreated: list[str] = []
    servers: list[ThreadingHTTPServer] = []
    kong_text = _kong_file(lab).read_text(encoding="utf-8") if _is_kong(lab) else ""
    try:
        kong_changes = [c for c in changes if c.kind.startswith("kong_")]
        if kong_changes:
            data = yaml.safe_load(kong_text)
            for change in kong_changes:
                _apply_kong(data, change)
            _kong_file(lab).write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
            _compose(lab, "up", "-d", "--force-recreate", "--wait", _KONG_SERVICE)
        for change in changes:
            fields = change.model_extra or {}
            if change.kind == "compose_env":
                service = str(fields["service"])
                override = {"services": {service: {"environment": fields["environment"]}}}
                with tempfile.NamedTemporaryFile(
                    "w", suffix=".yaml", delete=False, encoding="utf-8"
                ) as extra:
                    yaml.safe_dump(override, extra)
                _compose(
                    lab,
                    "-f",
                    _COMPOSE_FILE,
                    "-f",
                    extra.name,
                    "up",
                    "-d",
                    "--force-recreate",
                    "--wait",
                    service,
                )
                Path(extra.name).unlink()
                recreated.append(service)
            elif change.kind == "stand_in_admin_api":
                servers.append(_stand_in(str(fields["listen"]), dict(fields["answer"])))
            elif change.kind == "apisix_admin":
                _apisix_call(lab, str(fields["method"]), str(fields["path"]), fields.get("body"))
            elif change.kind == "stop_container":
                subprocess.run(["docker", "stop", fields["container"]], check=True)  # noqa: S603, S607
                stopped.append(str(fields["container"]))
        yield
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for container in stopped:
            subprocess.run(["docker", "start", container], check=True)  # noqa: S603, S607
        for service in recreated:
            if service != _KONG_SERVICE:
                _compose(lab, "up", "-d", "--force-recreate", "--wait", service)
        if _is_kong(lab):
            _kong_file(lab).write_text(kong_text, encoding="utf-8")
            _compose(lab, "up", "-d", "--force-recreate", "--wait", _KONG_SERVICE)
        else:
            _apisix_restore(lab, before)
        after = lab_state(lab)
        if after != before:
            raise SystemExit(f"STOP: lab {lab} is not back to its state after variant {variant}")
        console.print(f"  [green]lab {lab} back to its state[/green]", highlight=False)


def _stand_in(listen: str, answer: dict[str, Any]) -> ThreadingHTTPServer:
    """Start a local server answering every GET with one fixed JSON answer."""
    host, port = listen.rsplit(":", 1)
    body = json.dumps(answer.get("body")).encode("utf-8")
    status = int(answer.get("status", 200))

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 -- the name http.server calls
            """Answer with the fixed answer."""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            """Stay quiet."""

    server = ThreadingHTTPServer((host, int(port)), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _apisix_admin() -> tuple[httpx.Client, str]:
    """A client for APISIX's Admin API with the admin key (the tool's own key only reads)."""
    client, url = _admin_client("forgejo-apisix")
    client.headers["X-API-KEY"] = os.environ[_APISIX_ADMIN_KEY_VAR]
    return client, url


def _apisix_call(lab: str, method: str, path: str, body: object) -> None:
    """One call to APISIX's Admin API; raise unless it succeeds."""
    del lab
    client, url = _apisix_admin()
    with client:
        answer = client.request(method, f"{url}/{path}", json=body)
    if answer.status_code >= 300:  # noqa: PLR2004
        raise RuntimeError(f"APISIX {method} {path}: {answer.status_code} {answer.text[:200]}")


def _apisix_restore(lab: str, before: dict[str, Any]) -> None:
    """Apply setup.sh again, then delete every object the variant created."""
    _compose(lab, "up", _APISIX_SETUP_SERVICE)
    client, url = _apisix_admin()
    with client:
        for name in _APISIX_COLLECTIONS:
            known = {key for key, _ in before[name]}
            for entry in client.get(f"{url}/{name}").json()["list"]:
                key = str(entry.get("key", ""))
                if key not in known:
                    client.delete(f"{url}/{name}/{key.rsplit('/', 1)[-1]}")


# ---------------------------------------------------------------------------
# Running the tool and reading the cases
# ---------------------------------------------------------------------------


def _set_dotted(config: dict[str, Any], dotted: str, value: object) -> None:
    """Set a dotted key ("tests.domain_3.test_3_3.x") in a configuration."""
    node = config
    *parents, last = dotted.split(".")
    for part in parents:
        node = node.setdefault(part, {})
    node[last] = value


def edited_spec(lab: str, edit: SpecEdit, out_dir: Path) -> Path:
    """Read the lab's specification as its configuration does, edit it, write the copy."""
    source = lab_config(lab)["specification"]
    if source.get("path"):
        spec = json.loads((ROOT / source["path"]).read_text(encoding="utf-8"))
    else:
        tls = source.get("tls") or {}
        verify: str | bool = str(ROOT / tls["ca_bundle"]) if tls.get("ca_bundle") else True
        spec = httpx.get(str(source["url"]), verify=verify, timeout=_HTTP_TIMEOUT * 6).json()
    spec.update(edit.set)
    if edit.drop_plain_get:
        for path in list(spec.get("paths", {})):
            if "{" not in path:
                spec["paths"][path].pop("get", None)
                if not set(spec["paths"][path]) - {"parameters"}:
                    del spec["paths"][path]
    for dropped in edit.drop_operations:
        wanted = set(dropped.within_parameters)
        for path in list(spec.get("paths", {})):
            if set(re.findall(r"\{([^}]+)\}", path)) != wanted:
                continue
            for method in dropped.methods:
                spec["paths"][path].pop(method, None)
            if not set(spec["paths"][path]) - {"parameters"}:
                del spec["paths"][path]
    if edit.operations_security is not None:
        for item in spec.get("paths", {}).values():
            for method, operation in item.items():
                if method != "parameters" and isinstance(operation, dict):
                    operation["security"] = edit.operations_security
    for added in edit.add_operations:
        spec.setdefault("paths", {}).setdefault(added.path, {})[added.method] = added.operation
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "specification.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def run_tool(group: Group, out_dir: Path, spec_path: Path | None) -> dict[str, Any]:
    """Run the group's tests on its lab; return the report (apiguard_report.json)."""
    config = copy.deepcopy(lab_config(group.lab))
    if spec_path is not None:
        timeout = config["specification"].get("timeout")
        config["specification"] = {"path": str(spec_path)}
        if timeout is not None:
            config["specification"]["timeout"] = timeout
    config.setdefault("execution", {})["test_ids"] = group.tests
    config.setdefault("output", {})["directory"] = str(out_dir)
    for dotted, value in group.config.items():
        _set_dotted(config, dotted, value)
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
        yaml.safe_dump(config, tmp, sort_keys=False)
    command = [sys.executable, "-m", "src.cli", "run", "-c", tmp.name, "--no-banner"]
    log = out_dir / "run.log"
    out_dir.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as handle:
        subprocess.run(command, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT, check=False)  # noqa: S603
    Path(tmp.name).unlink()
    report_file = out_dir / "apiguard_report.json"
    if not report_file.exists():
        last = log.read_text(encoding="utf-8").strip().splitlines()[-1:] or ["(empty log)"]
        return {"all_rows": [], "no_report": f"the run produced no report: {last[0][:200]}"}
    report: dict[str, Any] = json.loads(report_file.read_text("utf-8"))
    return report


def _case_text(case: dict[str, Any]) -> str:
    """A recorded case, as the result shows it."""
    parts = [case["outcome"], case["detail"], case.get("confidence")]
    return " ".join(p for p in parts if p)


def judge(test: str, entry: CaseEntry, report: dict[str, Any]) -> dict[str, Any]:
    """Compare one case with what its test recorded."""
    row = next((r for r in report.get("all_rows", []) if r["test_id"] == test), None)
    expected = entry.expected
    result: dict[str, Any] = {
        "test": test,
        "id": entry.id,
        "situation": entry.situation,
        "expected": _case_text(expected.model_dump(mode="json")),
        "lab": entry.lab,
        "variant": entry.variant,
        "how": entry.how,
    }
    if row is None:
        return {
            **result,
            "observed": [str(report.get("no_report", "the test did not run"))],
            "verdict": None,
            "result": _DIFFERENT,
        }
    subs = [s for s in row["sub_tests"] if entry.sub_test in ("*", s["name"])]
    observed = [_case_text(c) for s in subs for c in s.get("cases", [])]
    hit = any(
        c["outcome"] == expected.outcome.value
        and c["detail"] == expected.detail
        and c.get("confidence") == expected.confidence
        for s in subs
        for c in s.get("cases", [])
    )
    computed, _ = combine_sub_tests([SubTestResult.model_validate(s) for s in row["sub_tests"]])
    verdict = row["status"]
    if row["sub_tests"] and verdict not in (TestStatus.ERROR.value, TestStatus.SKIP.value):
        verdict_ok = computed.value == verdict
    else:
        verdict_ok = True
    return {
        **result,
        "observed": observed or [f"none (test {verdict}: {row.get('skip_reason') or ''})"],
        "verdict": verdict,
        "verdict_from_cases": verdict_ok,
        "result": _OK if hit and verdict_ok else _DIFFERENT,
    }


# ---------------------------------------------------------------------------
# The campaign
# ---------------------------------------------------------------------------


def _git(*args: str) -> str:
    """Output of a git command in the repository."""
    done = subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True)  # noqa: S603, S607
    return done.stdout.strip()


def collect(tests: list[str] | None, lab: str | None) -> tuple[list[Group], list[dict[str, Any]]]:
    """The groups to run and the cases not producible, from the case files."""
    groups: dict[tuple[str, str, str, str], Group] = {}
    excluded: list[dict[str, Any]] = []
    for test in declared_cases():
        if tests and test not in tests:
            continue
        case_file = load_case_file(test)
        for entry in case_file.cases if case_file else []:
            if entry.not_producible is not None:
                excluded.append(
                    {
                        "test": test,
                        "id": entry.id,
                        "situation": entry.situation,
                        "group": entry.not_producible.group,
                        "reason": entry.not_producible.reason,
                    }
                )
            elif entry.variant and (lab is None or entry.lab == lab):
                spec = entry.spec.model_dump_json() if entry.spec else ""
                key = (entry.lab, entry.variant, json.dumps(entry.config, sort_keys=True), spec)
                group = groups.setdefault(
                    key, Group(entry.lab, entry.variant, dict(entry.config), entry.spec)
                )
                group.cases.append((test, entry))
    order = {name: i for i, name in enumerate(LABS)}
    ordered = sorted(
        groups.values(), key=lambda g: (order[g.lab], g.variant != AS_BUILT, g.variant)
    )
    return ordered, excluded


def write_results(
    stamp: str, meta: dict[str, Any], results: list[dict[str, Any]], excluded: list[dict[str, Any]]
) -> Path:
    """Write the JSON and the readable Markdown of a campaign; return the Markdown's path."""
    RESULTS_DIR.mkdir(exist_ok=True)
    base = RESULTS_DIR / stamp
    payload = {"meta": meta, "cases": results, "not_producible": excluded}
    base.with_suffix(".json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    ok = sum(r["result"] == _OK for r in results)
    lines = [
        f"# Validation run {meta['date']}",
        "",
        f"Commit `{meta['commit']}`{' (working tree with changes)' if meta['dirty'] else ''}, "
        f"tool {meta['tool_version']}.",
        "",
        f"Cases run {len(results)}: as expected {ok}, different {len(results) - ok}; "
        f"not producible {len(excluded)}.",
        "",
    ]
    run_by_id = {(r["test"], r["id"]): r for r in results}
    excluded_by_id = {(e["test"], e["id"]): e for e in excluded}
    for test, (name, cases) in declared_cases().items():
        rows = [c.id for c in cases if (test, c.id) in run_by_id or (test, c.id) in excluded_by_id]
        if not rows:
            continue
        lines += [f"## {test} {name}", "", "| Case | Expected | Observed | How | Result |"]
        lines.append("|---|---|---|---|---|")
        for case_id in rows:
            r = run_by_id.get((test, case_id))
            if r is not None:
                observed = "<br>".join(r["observed"])
                lines.append(
                    f"| {r['id']}<br>*{r['situation']}* | {r['expected']} | {observed} | "
                    f"{r['lab']}, variant {r['variant']}: {r['how']} | **{r['result']}** |"
                )
                continue
            e = excluded_by_id[(test, case_id)]
            lines.append(
                f"| {e['id']}<br>*{e['situation']}* | - | - | not producible ({e['group']}): "
                f"{e['reason']} | - |"
            )
        lines.append("")
    path = base.with_suffix(".md")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def main() -> int:
    """Run the campaign the arguments select; exit 1 when a case is different."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[1] if __doc__ else None)
    parser.add_argument("--test", nargs="*", help="Only these tests.")
    parser.add_argument("--lab", choices=LABS, help="Only the cases of this lab.")
    parser.add_argument(
        "--reset", nargs="*", choices=LABS, default=[], help="Reset these labs first (data lost)."
    )
    args = parser.parse_args()
    load_dotenv(ENV_FILE, override=False)
    commit = _git("rev-parse", "--short", "HEAD")
    dirty = bool(_git("status", "--porcelain"))
    now = datetime.now(UTC)
    stamp = f"{now:%Y%m%d-%H%M}-{commit}{'-dirty' if dirty else ''}"
    meta = {"date": f"{now:%Y-%m-%d %H:%M} UTC", "commit": commit, "dirty": dirty}
    meta["tool_version"] = __version__
    for lab in args.reset:
        gateway, setups = _RESET[lab]
        console.print(f"reset {lab}", highlight=False)
        _compose(lab, "down", "-v")
        _compose(lab, "up", "-d", "--wait", gateway)
        for setup in setups:
            _compose(lab, "up", setup)
    meta["reset"] = list(args.reset)
    groups, excluded = collect(args.test, args.lab)
    results: list[dict[str, Any]] = []
    work = RESULTS_DIR / f"{stamp}-runs"
    for index, group in enumerate(groups, start=1):
        console.print(
            f"[{index}/{len(groups)}] {group.lab}, variant {group.variant}, "
            f"config {group.config or '-'}{', edited specification' if group.spec else ''}: "
            f"tests {', '.join(group.tests)}",
            highlight=False,
        )
        out_dir = work / f"{index:03d}"
        # A variant that stops a container may stop what serves the specification:
        # the run then reads a copy taken before (the same specification).
        stops = any(
            c.kind == "stop_container"
            for c in (
                load_variants(group.lab)[group.variant].changes if group.variant != AS_BUILT else []
            )
        )
        spec = group.spec if group.spec is not None else (SpecEdit() if stops else None)
        spec_path = edited_spec(group.lab, spec, out_dir) if spec is not None else None
        with applied(group.lab, group.variant):
            report = run_tool(group, out_dir, spec_path)
        for test, entry in group.cases:
            outcome = judge(test, entry, report)
            results.append(outcome)
            mark = "green" if outcome["result"] == _OK else "red"
            console.print(
                f"  [{mark}]{outcome['result']}[/{mark}] {test} {entry.id}", highlight=False
            )
    path = write_results(stamp, meta, results, excluded)
    console.print(f"Result: {path.relative_to(ROOT)}", highlight=False)
    return 0 if all(r["result"] == _OK for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
