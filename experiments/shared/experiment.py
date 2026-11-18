"""
experiments/shared/experiment.py

What every experiment shares: the labs and their reset, a run of the tool with
one live line, and the naming of a result (a campaign or a trial).

A campaign (every case or lab, on a clean commit) starts from freshly reset labs
and its result is committed, replacing the previous one; a trial (only some
tests or labs: -partial; a working tree with changes: -dirty) stays local, the
latest only. The raw reports of each run (<stamp>-runs/) stay local.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # noqa: S404 -- the experiments drive docker, git and the tool
import sys
import tempfile
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from rich.console import Console

ROOT: Path = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src import __version__  # noqa: E402

console = Console()
LAB_DIR: Path = ROOT / "test-environments"
ENV_FILE: Path = ROOT / ".env"
LABS: tuple[str, ...] = ("forgejo-kong", "crapi-kong", "forgejo-apisix")
# The full reset of a lab (docs/project/maintainer-commands.md, Test Labs): its data
# removed, the gateway service started, then the setup services, in order.
_RESET: dict[str, tuple[str, tuple[str, ...]]] = {
    "forgejo-kong": ("kong", ("forgejo-setup",)),
    "crapi-kong": ("kong", ("crapi-setup",)),
    "forgejo-apisix": ("apisix", ("forgejo-setup", "apisix-setup")),
}
_DIRTY: str = "-dirty"
_PARTIAL: str = "-partial"
RUNS_SUFFIX: str = "-runs"
_RESULT_SUFFIXES: frozenset[str] = frozenset({".md", ".json"})
# The tool's console: a test announced as running, and a test line when it ends.
_RUNNING_MARK: str = "running (limit"
_TICK_SECONDS: float = 1.0
_TEST_LINE: re.Pattern[str] = re.compile(r"^\[\s*(\d+)/(\d+)\]\s+(\S+)")


@dataclass(frozen=True)
class Stamp:
    """Who ran what: the name of a result and the facts its header states."""

    name: str
    campaign: bool
    meta: dict[str, Any]


def start(*, partial: bool) -> Stamp:
    """
    The stamp of a run starting now, and the environment it needs (.env).

    Args:
        partial: Whether the run covers only some tests or labs.
    """
    load_dotenv(ENV_FILE, override=False)
    commit = git("rev-parse", "--short", "HEAD")
    dirty = bool(git("status", "--porcelain"))
    now = datetime.now(UTC)
    name = f"{now:%Y%m%d-%H%M}-{commit}{_DIRTY if dirty else ''}{_PARTIAL if partial else ''}"
    meta = {
        "date": f"{now:%Y-%m-%d %H:%M} UTC",
        "commit": commit,
        "dirty": dirty,
        "partial": partial,
        "tool_version": __version__,
    }
    return Stamp(name=name, campaign=not (dirty or partial), meta=meta)


def header(stamp: Stamp) -> str:
    """The sentence naming the commit, the tool and the kind of result."""
    meta = stamp.meta
    changes = " (working tree with changes)" if meta["dirty"] else ""
    part = "; only some tests or labs" if meta["partial"] else ""
    kind = "Campaign" if stamp.campaign else "Trial"
    return f"{kind} at commit `{meta['commit']}`{changes}, tool {meta['tool_version']}{part}."


def git(*args: str) -> str:
    """Output of a git command in the repository."""
    done = subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True)  # noqa: S603, S607
    return done.stdout.strip()


def lab_config(lab: str) -> dict[str, Any]:
    """The tool configuration of a lab, as committed."""
    loaded: dict[str, Any] = yaml.safe_load(
        (LAB_DIR / lab / "config.yaml").read_text(encoding="utf-8")
    )
    return loaded


def compose(lab: str, *args: str) -> None:
    """Run docker compose in the lab's folder; raise when it fails."""
    command = ["docker", "compose", "--env-file", str(ENV_FILE), *args]
    subprocess.run(command, cwd=LAB_DIR / lab, check=True, capture_output=True)  # noqa: S603


def reset_lab(lab: str) -> None:
    """The lab's full reset: its data removed, then built again as committed."""
    gateway, setups = _RESET[lab]
    with console.status(f"reset {lab}", spinner="dots"):
        compose(lab, "down", "-v")
        compose(lab, "up", "-d", "--wait", gateway)
        for setup in setups:
            compose(lab, "up", setup)
    console.print(f"reset {lab}: done", highlight=False)


def run_tool(config: dict[str, Any], out_dir: Path, label: str) -> dict[str, Any]:
    """
    Run the tool with a configuration; return its report (apiguard_report.json).

    The report, the evidence and the tool's console (run.log) are written to
    out_dir. Without a report, the result says why (the log's last line).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    config.setdefault("output", {})["directory"] = str(out_dir)
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
        yaml.safe_dump(config, tmp, sort_keys=False)
    command = [sys.executable, "-m", "src.cli", "run", "-c", tmp.name, "--no-banner"]
    log = out_dir / "run.log"
    try:
        _run_with_status(command, log, label)
    finally:
        Path(tmp.name).unlink()
    report_file = out_dir / "apiguard_report.json"
    if not report_file.exists():
        last = log.read_text(encoding="utf-8").strip().splitlines()[-1:] or ["(empty log)"]
        return {"all_rows": [], "no_report": f"the run produced no report: {last[0][:200]}"}
    report: dict[str, Any] = json.loads(report_file.read_text("utf-8"))
    return report


def _run_with_status(command: list[str], log: Path, label: str) -> None:
    """
    Run the tool, its output to the log, showing one live line meanwhile.

    The line (a terminal only; nothing in a file) names the run, the test the
    tool reached and the time elapsed, refreshed every second, so a slow test
    does not look stuck. It goes when the run ends.
    """
    started = datetime.now(UTC)
    progress = ["starting"]
    ended = threading.Event()

    def tick() -> None:
        """Refresh the line every second, the elapsed time moving during a slow test."""
        while not ended.wait(_TICK_SECONDS):
            elapsed = int((datetime.now(UTC) - started).total_seconds())
            status.update(f"{label}: {progress[0]}, {elapsed // 60}:{elapsed % 60:02d}")

    with (
        log.open("w", encoding="utf-8") as handle,
        console.status(f"{label}: starting", spinner="dots") as status,
        subprocess.Popen(  # noqa: S603
            command,
            cwd=ROOT,
            # Unbuffered: each line of the tool reaches the live line when printed.
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        ) as process,
    ):
        stream = process.stdout
        if stream is None:
            raise RuntimeError("the tool's output could not be read")
        ticker = threading.Thread(target=tick, daemon=True)
        ticker.start()
        try:
            for line in stream:
                handle.write(line)
                match = _TEST_LINE.match(line)
                if match is None:
                    continue
                number, total, test = match.groups()
                if _RUNNING_MARK in line:
                    progress[0] = f"running {test} ({number} of {total})"
                else:
                    progress[0] = f"{number} of {total} tests done (last {test})"
        finally:
            ended.set()
            ticker.join()


def write_result(results_dir: Path, stamp: Stamp, payload: dict[str, Any], markdown: str) -> Path:
    """
    Write a result (Markdown for the reader, JSON for the counts); keep only the latest.

    The earlier results of the same kind (campaign or trial) are removed, with
    their raw runs: git keeps the history of the committed campaigns.

    Returns:
        The Markdown's path.
    """
    results_dir.mkdir(parents=True, exist_ok=True)
    base = results_dir / stamp.name
    base.with_suffix(".json").write_text(
        json.dumps({"meta": stamp.meta, **payload}, indent=2), encoding="utf-8"
    )
    path = base.with_suffix(".md")
    path.write_text(markdown, encoding="utf-8")
    for item in results_dir.iterdir():
        stem = item.name.removesuffix(RUNS_SUFFIX).removesuffix(item.suffix)
        if item.name.startswith(stamp.name) or _is_trial(stem) == stamp.campaign:
            continue
        if item.is_dir() and item.name.endswith(RUNS_SUFFIX):
            shutil.rmtree(item)
        elif item.suffix in _RESULT_SUFFIXES:
            item.unlink()
    return path


def _is_trial(name: str) -> bool:
    """Whether a result's name is a trial's, not a campaign's."""
    return name.endswith((_DIRTY, _PARTIAL))


def latest(results_dir: Path) -> Path | None:
    """The latest result (JSON) in a folder, campaign or trial; None when there is none."""
    found = sorted(results_dir.glob("*.json")) if results_dir.exists() else []
    return found[-1] if found else None
