from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "traceroute-report",
    "name": "Traceroute Report",
    "category": "network_scanning",
    "summary": "Run traceroute/mtr and summarise hops.",
    "risk": "medium",
    "requires": ["traceroute"],
    "supports_json": True,
    "default_output": "traceroute-report/result.json",
    "handler": "traceroute_report",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
