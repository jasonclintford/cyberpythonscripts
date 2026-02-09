from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "hash-file",
    "name": "Hash File",
    "category": "forensics",
    "summary": "Compute file hashes with metadata.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "hash-file/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
