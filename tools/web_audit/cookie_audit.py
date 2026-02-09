from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "cookie-audit",
    "name": "Cookie Audit",
    "category": "web_audit",
    "summary": "Check Secure/HttpOnly/SameSite cookie flags.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "cookie-audit/result.json",
    "handler": "cookie_audit",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
