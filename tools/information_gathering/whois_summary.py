from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "whois-summary",
    "name": "WHOIS Summary",
    "category": "information_gathering",
    "summary": "WHOIS query with parsed registrar/date summary.",
    "risk": "low",
    "requires": ["whois"],
    "supports_json": True,
    "default_output": "whois-summary/result.json",
    "handler": "whois_summary",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
