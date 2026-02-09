from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "timeline-lite",
    "name": "Timeline Lite",
    "category": "forensics",
    "summary": "Generate filesystem timeline by mtime/ctime/atime.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "timeline-lite/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
