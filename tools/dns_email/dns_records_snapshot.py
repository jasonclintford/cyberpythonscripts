from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "dns-records-snapshot",
    "name": "DNS Records Snapshot",
    "category": "dns_email",
    "summary": "Collect A/AAAA/CNAME/MX/TXT/NS records.",
    "risk": "low",
    "requires": ["dig"],
    "supports_json": True,
    "default_output": "dns-records-snapshot/result.json",
    "handler": "dns_records_snapshot",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
