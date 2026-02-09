from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "pcap-summary",
    "name": "PCAP Summary",
    "category": "network_scanning",
    "summary": "Summarise pcap conversations and protocols via tshark.",
    "risk": "low",
    "requires": ["tshark"],
    "supports_json": True,
    "default_output": "pcap-summary/result.json",
    "handler": "pcap_summary",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
