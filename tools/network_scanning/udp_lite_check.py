from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "udp-lite-check",
    "name": "UDP Lite Check",
    "category": "network_scanning",
    "summary": "Small UDP checks for DNS/NTP/SNMP presence.",
    "risk": "medium",
    "requires": [],
    "supports_json": True,
    "default_output": "udp-lite-check/result.json",
    "handler": "udp_lite_check",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
