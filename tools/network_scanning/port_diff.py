from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "port-diff",
    "name": "Port Diff",
    "category": "network_scanning",
    "summary": "Diff two scan outputs and show changes.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "port-diff/result.json",
    "handler": "port_diff",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
