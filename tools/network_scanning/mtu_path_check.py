from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "mtu-path-check",
    "name": "MTU Path Check",
    "category": "network_scanning",
    "summary": "PMTU check with ping DF probes.",
    "risk": "medium",
    "requires": ["ping"],
    "supports_json": True,
    "default_output": "mtu-path-check/result.json",
    "handler": "mtu_path_check",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
