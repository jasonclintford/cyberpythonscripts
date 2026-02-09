from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "http-methods-check",
    "name": "HTTP Methods Check",
    "category": "web_audit",
    "summary": "Probe OPTIONS and common methods safely.",
    "risk": "medium",
    "requires": [],
    "supports_json": True,
    "default_output": "http-methods-check/result.json",
    "handler": "http_methods_check",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
