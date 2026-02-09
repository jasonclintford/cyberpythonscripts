from __future__ import annotations

import platform
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .io import read_json, write_json, write_text
from .paths import reports_root


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


@dataclass(slots=True)
class RunContext:
    tool_id: str
    args: list[str]
    run_id: str
    run_dir: Path
    started_at: str

    @property
    def stdout_log(self) -> Path:
        return self.run_dir / "stdout.log"

    @property
    def stderr_log(self) -> Path:
        return self.run_dir / "stderr.log"

    @property
    def run_json(self) -> Path:
        return self.run_dir / "run.json"


def start_run(
    tool_id: str,
    args: list[str],
    requires: list[str] | None = None,
    extra_meta: dict[str, Any] | None = None,
) -> RunContext:
    stamp = utc_stamp()
    run_dir = reports_root() / tool_id / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    run_id = f"{tool_id}-{stamp}"
    started_at = utc_now_iso()
    run = RunContext(
        tool_id=tool_id, args=args, run_id=run_id, run_dir=run_dir, started_at=started_at
    )
    payload: dict[str, Any] = {
        "run_id": run_id,
        "tool_id": tool_id,
        "args": args,
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "requires": requires or [],
        "started_at": started_at,
        "finished_at": None,
        "status": "running",
        "result_files": [],
    }
    if extra_meta:
        payload.update(extra_meta)
    write_json(run.run_json, payload)
    return run


def add_result_file(run: RunContext, path: Path) -> None:
    payload = read_json(run.run_json)
    relative = str(path.relative_to(run.run_dir))
    result_files = payload.setdefault("result_files", [])
    if relative not in result_files:
        result_files.append(relative)
    write_json(run.run_json, payload)


def write_result_json(run: RunContext, filename: str, data: Any) -> Path:
    path = run.run_dir / filename
    write_json(path, data)
    add_result_file(run, path)
    return path


def write_result_text(run: RunContext, filename: str, content: str) -> Path:
    path = run.run_dir / filename
    write_text(path, content)
    add_result_file(run, path)
    return path


def finish_run(run: RunContext, status: str = "ok", summary: str | None = None) -> None:
    payload = read_json(run.run_json)
    payload["status"] = status
    payload["finished_at"] = utc_now_iso()
    if summary is not None:
        payload["summary"] = summary
    write_json(run.run_json, payload)


def find_run(run_id: str) -> Path | None:
    base = reports_root()
    if not base.exists():
        return None
    for run_json in base.glob("*/*/run.json"):
        payload = read_json(run_json)
        if payload.get("run_id") == run_id:
            return run_json.parent
    # Convenience: allow direct timestamp or leaf directory lookup.
    for leaf in base.glob(f"*/*{run_id}*"):
        if leaf.is_dir():
            return leaf
    return None
