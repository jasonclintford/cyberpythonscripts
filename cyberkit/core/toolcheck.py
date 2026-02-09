from __future__ import annotations

import shutil
import subprocess


def which(command: str) -> str | None:
    return shutil.which(command)


def probe_version(command: str, flags: list[str] | None = None, timeout: int = 5) -> str:
    if which(command) is None:
        return "missing"
    args = [command] + (flags if flags is not None else ["--version"])
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return "unknown"
    output = (completed.stdout or completed.stderr).strip().splitlines()
    return output[0] if output else "unknown"


def is_installed(command: str) -> bool:
    return which(command) is not None
