from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "spf-check",
    "name": "SPF Check",
    "category": "dns_email",
    "summary": "Parse SPF and flag risky mechanisms.",
    "risk": "low",
    "requires": ["dig"],
    "supports_json": True,
    "default_output": "spf-check/result.json",
    "handler": "spf_check",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
