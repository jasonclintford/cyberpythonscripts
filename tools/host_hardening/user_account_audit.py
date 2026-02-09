from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "user-account-audit",
    "name": "User Account Audit",
    "category": "host_hardening",
    "summary": "Audit local users, shell access, and account state.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "user-account-audit/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
