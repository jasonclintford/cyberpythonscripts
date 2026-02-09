from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "systemd-failed-units",
    "name": "Systemd Failed Units",
    "category": "logs_monitoring",
    "summary": "Report failed services and last errors.",
    "risk": "low",
    "requires": ["systemctl"],
    "supports_json": True,
    "default_output": "systemd-failed-units/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
