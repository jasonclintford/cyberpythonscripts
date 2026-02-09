from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "asn-lookup",
    "name": "ASN Lookup",
    "category": "information_gathering",
    "summary": "Map IP addresses to ASN from local WHOIS data.",
    "risk": "low",
    "requires": ["whois"],
    "supports_json": True,
    "default_output": "asn-lookup/result.json",
    "handler": "asn_lookup",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
