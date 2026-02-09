from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "cron-audit",
    "name": "Cron Audit",
    "category": "host_hardening",
    "summary": "Enumerate cron jobs and writable-path risks.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "cron-audit/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
