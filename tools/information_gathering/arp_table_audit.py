from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "arp-table-audit",
    "name": "ARP Table Audit",
    "category": "information_gathering",
    "summary": "Snapshot ARP table and flag duplicate mappings.",
    "risk": "low",
    "requires": ["ip"],
    "supports_json": True,
    "default_output": "arp-table-audit/result.json",
    "handler": "arp_table_audit",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
