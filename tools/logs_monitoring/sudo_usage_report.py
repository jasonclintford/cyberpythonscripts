from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "sudo-usage-report",
    "name": "Sudo Usage Report",
    "category": "logs_monitoring",
    "summary": "Extract and summarise sudo usage events.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "sudo-usage-report/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
