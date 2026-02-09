from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "tool-versions",
    "name": "Tool Versions",
    "category": "misc",
    "summary": "Print versions of common external utilities.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "tool-versions/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
