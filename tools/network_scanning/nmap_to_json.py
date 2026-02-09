from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "nmap-to-json",
    "name": "Nmap To JSON",
    "category": "network_scanning",
    "summary": "Convert nmap XML to JSON summary.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "nmap-to-json/result.json",
    "handler": "nmap_to_json",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
