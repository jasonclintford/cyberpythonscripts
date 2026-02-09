from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "domain-typo-monitor",
    "name": "Domain Typo Monitor",
    "category": "dns_email",
    "summary": "Generate minimal typo variants and check resolution.",
    "risk": "low",
    "requires": ["dig"],
    "supports_json": True,
    "default_output": "domain-typo-monitor/result.json",
    "handler": "domain_typo_monitor",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
