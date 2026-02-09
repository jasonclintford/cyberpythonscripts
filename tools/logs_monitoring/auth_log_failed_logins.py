from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "auth-log-failed-logins",
    "name": "Auth Log Failed Logins",
    "category": "logs_monitoring",
    "summary": "Summarise failed SSH logins by IP/user.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "auth-log-failed-logins/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
