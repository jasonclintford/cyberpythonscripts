from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "local-net-inventory",
    "name": "Local Net Inventory",
    "category": "information_gathering",
    "summary": "Collect interfaces, routes, DNS, ARP, and listening sockets.",
    "risk": "low",
    "requires": ["ip", "ss"],
    "supports_json": True,
    "default_output": "local-net-inventory/result.json",
    "handler": "local_net_inventory",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
