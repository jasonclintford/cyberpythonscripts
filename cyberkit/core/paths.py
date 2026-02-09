from __future__ import annotations

from pathlib import Path


def project_root() -> Path:
    # Resolve from the current working directory so reports/docs are local to execution context.
    return Path.cwd()


def reports_root() -> Path:
    root = project_root() / "reports"
    root.mkdir(parents=True, exist_ok=True)
    return root


def docs_root() -> Path:
    root = project_root() / "docs"
    root.mkdir(parents=True, exist_ok=True)
    return root
