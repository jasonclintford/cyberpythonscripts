from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "tcp-connect-scan",
    "name": "TCP Connect Scan",
    "category": "network_scanning",
    "summary": "Pure Python TCP connect scan for small scopes.",
    "risk": "medium",
    "requires": [],
    "supports_json": True,
    "default_output": "tcp-connect-scan/result.json",
    "handler": "tcp_connect_scan",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
