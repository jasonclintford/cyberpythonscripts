from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "dkim-selector-check",
    "name": "DKIM Selector Check",
    "category": "dns_email",
    "summary": "Check common DKIM selectors for TXT records.",
    "risk": "low",
    "requires": ["dig"],
    "supports_json": True,
    "default_output": "dkim-selector-check/result.json",
    "handler": "dkim_selector_check",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
