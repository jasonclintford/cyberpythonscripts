from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path
from typing import Any

from cyberkit.core.exec import Completed
from cyberkit.core.exec import run as exec_run
from cyberkit.core.io import write_json
from cyberkit.core.reporting import (
    RunContext,
    finish_run,
    start_run,
    write_result_json,
    write_result_text,
)
from cyberkit.core.toolcheck import is_installed
from cyberkit.ui.renderers import SAFETY_NOTICE


def build_parser(
    meta: dict[str, Any],
    purpose: str,
    examples: list[str],
    add_json: bool = True,
    add_dry_run: bool = True,
) -> argparse.ArgumentParser:
    epilog_lines = [SAFETY_NOTICE, "", "Examples:"]
    epilog_lines.extend([f"  {line}" for line in examples])
    parser = argparse.ArgumentParser(
        prog=meta["id"],
        description=purpose,
        epilog="\n".join(epilog_lines),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    if add_json:
        parser.add_argument(
            "--json", action="store_true", help="Print result payload to stdout as JSON."
        )
    if add_dry_run:
        parser.add_argument(
            "--dry-run", action="store_true", help="Show planned actions without executing."
        )
    parser.add_argument("--timeout", type=int, default=10, help="Operation timeout in seconds.")
    return parser


def check_requirements(meta: dict[str, Any]) -> list[str]:
    requires = meta.get("requires", [])
    return [cmd for cmd in requires if not is_installed(cmd)]


def create_run(meta: dict[str, Any], argv: list[str]) -> RunContext:
    return start_run(tool_id=str(meta["id"]), args=argv, requires=list(meta.get("requires", [])))


def write_payload(run: RunContext, payload: dict[str, Any], print_json: bool = False) -> None:
    write_result_json(run, "result.json", payload)
    if print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))


def write_note(run: RunContext, note: str) -> None:
    write_result_text(run, "summary.txt", note)


def fail(meta: dict[str, Any], message: str, code: int = 1) -> int:
    print(f"[{meta['id']}] error: {message}", file=sys.stderr)
    return code


def complete(run: RunContext, summary: str, status: str = "ok") -> int:
    finish_run(run, status=status, summary=summary)
    print(f"Run complete: {run.run_id}")
    print(f"Report: {run.run_dir}")
    return 0 if status == "ok" else 1


def dry_run(meta: dict[str, Any], plan: str) -> int:
    print(f"[{meta['id']}] dry-run")
    print(plan)
    return 0


def probe_tcp_banner(host: str, port: int, timeout: float) -> str:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        try:
            data = sock.recv(1024)
        except TimeoutError:
            return ""
        return data.decode("utf-8", errors="replace").strip()


def rate_sleep(rate: float) -> None:
    if rate <= 0:
        return
    time.sleep(1.0 / rate)


def run_command(
    run: RunContext,
    cmd: list[str],
    timeout: int,
    dry_run_flag: bool = False,
    allow_sudo: bool = False,
) -> Completed | None:
    if dry_run_flag:
        write_note(run, "dry-run mode; command not executed")
        return None
    completed = exec_run(
        cmd,
        timeout=timeout,
        stdout_log=run.stdout_log,
        stderr_log=run.stderr_log,
        allow_sudo=allow_sudo,
    )
    command_record = {
        "command": cmd,
        "returncode": completed.returncode,
        "duration_s": completed.duration_s,
        "timed_out": completed.timed_out,
    }
    write_json(run.run_dir / "command.json", command_record)
    return completed


def parse_targets(raw: str) -> list[str]:
    if not raw:
        return []
    return [piece.strip() for piece in raw.split(",") if piece.strip()]


def load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
