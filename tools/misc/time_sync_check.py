from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "time-sync-check",
    "name": "Time Sync Check",
    "category": "misc",
    "summary": "Check NTP/chrony sync status and drift.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "time-sync-check/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
