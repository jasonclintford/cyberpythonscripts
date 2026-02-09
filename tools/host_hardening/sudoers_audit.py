from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "sudoers-audit",
    "name": "Sudoers Audit",
    "category": "host_hardening",
    "summary": "Identify risky sudoers NOPASSWD/ALL rules.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "sudoers-audit/result.json",
    "handler": "sudoers_audit",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
