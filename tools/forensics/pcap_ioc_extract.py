from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "pcap-ioc-extract",
    "name": "PCAP IOC Extract",
    "category": "forensics",
    "summary": "Extract DNS/SNI/HTTP hosts from PCAP.",
    "risk": "low",
    "requires": ["tshark"],
    "supports_json": True,
    "default_output": "pcap-ioc-extract/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
