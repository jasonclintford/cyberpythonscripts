from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "ioc-grep",
    "name": "IOC Grep",
    "category": "logs_monitoring",
    "summary": "Search logs for IOC indicators from list.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "ioc-grep/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
