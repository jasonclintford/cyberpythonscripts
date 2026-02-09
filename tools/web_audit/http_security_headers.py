from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "http-security-headers",
    "name": "HTTP Security Headers",
    "category": "web_audit",
    "summary": "Check major HTTP security headers.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "http-security-headers/result.json",
    "handler": "http_security_headers",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
