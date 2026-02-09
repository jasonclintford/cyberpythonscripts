from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "strings-plus",
    "name": "Strings Plus",
    "category": "forensics",
    "summary": "Extract strings with context and entropy hints.",
    "risk": "low",
    "requires": ["strings"],
    "supports_json": True,
    "default_output": "strings-plus/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
