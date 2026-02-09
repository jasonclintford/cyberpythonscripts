from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "auth-log-success-logins",
    "name": "Auth Log Success Logins",
    "category": "logs_monitoring",
    "summary": "Summarise successful logins and anomalies.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "auth-log-success-logins/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
