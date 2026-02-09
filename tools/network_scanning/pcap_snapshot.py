from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "pcap-snapshot",
    "name": "PCAP Snapshot",
    "category": "network_scanning",
    "summary": "Short tcpdump capture with safe defaults.",
    "risk": "medium",
    "requires": ["tcpdump"],
    "supports_json": True,
    "default_output": "pcap-snapshot/result.json",
    "handler": "pcap_snapshot",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
