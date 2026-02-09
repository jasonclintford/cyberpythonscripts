from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class Completed:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool


def run(
    cmd: list[str],
    timeout: int = 30,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    stdout_log: Path | None = None,
    stderr_log: Path | None = None,
    allow_sudo: bool = False,
) -> Completed:
    if not cmd:
        raise ValueError("Command cannot be empty.")
    if cmd[0] == "sudo" and not allow_sudo:
        raise PermissionError(
            "Refusing to auto-sudo. Re-run with --allow-sudo if explicitly intended."
        )

    start = time.monotonic()
    try:
        completed = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        timed_out = False
        returncode = completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        timed_out = True
        returncode = 124
    except OSError as exc:
        stdout = ""
        stderr = str(exc)
        timed_out = False
        returncode = 127

    duration_s = time.monotonic() - start

    if stdout_log is not None:
        stdout_log.parent.mkdir(parents=True, exist_ok=True)
        stdout_log.write_text(stdout, encoding="utf-8")
    if stderr_log is not None:
        stderr_log.parent.mkdir(parents=True, exist_ok=True)
        stderr_log.write_text(stderr, encoding="utf-8")

    return Completed(
        command=cmd,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_s=duration_s,
        timed_out=timed_out,
    )
