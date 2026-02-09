from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "dnssec-check",
    "name": "DNSSEC Check",
    "category": "dns_email",
    "summary": "Validate DNSSEC indicators via dig +dnssec.",
    "risk": "low",
    "requires": ["dig"],
    "supports_json": True,
    "default_output": "dnssec-check/result.json",
    "handler": "dnssec_check",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
