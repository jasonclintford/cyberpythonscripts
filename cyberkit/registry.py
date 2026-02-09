from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

REQUIRED_META_FIELDS = {
    "id",
    "name",
    "category",
    "summary",
    "risk",
    "requires",
    "supports_json",
    "default_output",
}

_CACHE: list[ToolRecord] | None = None


@dataclass(slots=True)
class ToolRecord:
    tool_id: str
    path: Path
    module: ModuleType
    meta: dict[str, Any]


def tools_root() -> Path:
    from cyberkit.core.paths import project_root

    env = os.environ.get("CYBERKIT_TOOLS_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return (project_root() / "tools").resolve()


def _load_module(path: Path) -> ModuleType | None:
    module_name = "cyberkit_tool_" + "_".join(path.with_suffix("").parts[-3:])
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        return None
    return module


def _valid_meta(meta: dict[str, Any]) -> bool:
    return REQUIRED_META_FIELDS.issubset(set(meta))


def discover_tools(refresh: bool = False) -> list[ToolRecord]:
    global _CACHE
    if _CACHE is not None and not refresh:
        return _CACHE

    root = tools_root()
    records: list[ToolRecord] = []
    if not root.exists():
        _CACHE = []
        return _CACHE

    for path in sorted(root.rglob("*.py")):
        if path.name.startswith("_"):
            continue
        module = _load_module(path)
        if module is None:
            continue
        meta = getattr(module, "TOOL_META", None)
        main_fn = getattr(module, "main", None)
        if not isinstance(meta, dict) or not _valid_meta(meta) or not callable(main_fn):
            continue
        record = ToolRecord(tool_id=str(meta["id"]), path=path, module=module, meta=meta)
        records.append(record)

    _CACHE = records
    return records


def by_id(tool_id: str) -> ToolRecord | None:
    for record in discover_tools():
        if record.tool_id == tool_id:
            return record
    return None


def grouped_by_category(records: list[ToolRecord] | None = None) -> dict[str, list[ToolRecord]]:
    items = records if records is not None else discover_tools()
    grouped: dict[str, list[ToolRecord]] = {}
    for record in items:
        grouped.setdefault(str(record.meta["category"]), []).append(record)
    for key in grouped:
        grouped[key].sort(key=lambda r: r.tool_id)
    return dict(sorted(grouped.items(), key=lambda kv: kv[0]))


def search(query: str) -> list[ToolRecord]:
    needle = query.lower().strip()
    if not needle:
        return []
    matched: list[ToolRecord] = []
    for record in discover_tools():
        tags = " ".join(record.meta.get("tags", []))
        haystack = " ".join(
            [
                record.tool_id,
                str(record.meta.get("name", "")),
                str(record.meta.get("summary", "")),
                tags,
            ]
        ).lower()
        if needle in haystack:
            matched.append(record)
    return matched


def filter_records(category: str | None = None, risk: str | None = None) -> list[ToolRecord]:
    rows = discover_tools()
    if category:
        rows = [r for r in rows if str(r.meta.get("category")) == category]
    if risk:
        rows = [r for r in rows if str(r.meta.get("risk")) == risk]
    return rows


def dependency_set(records: list[ToolRecord] | None = None) -> set[str]:
    deps: set[str] = set()
    for record in records if records is not None else discover_tools():
        for dep in record.meta.get("requires", []):
            deps.add(str(dep))
    return deps
