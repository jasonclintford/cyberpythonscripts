from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "world-writable-finder",
    "name": "World Writable Finder",
    "category": "host_hardening",
    "summary": "Find world-writable files in selected paths.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "world-writable-finder/result.json",
    "handler": "world_writable_finder",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
