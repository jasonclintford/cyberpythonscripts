from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "nmap-quick",
    "name": "Nmap Quick",
    "category": "network_scanning",
    "summary": "Fast top-ports nmap scan with safe defaults.",
    "risk": "medium",
    "requires": ["nmap"],
    "supports_json": True,
    "default_output": "nmap-quick/result.json",
    "handler": "nmap_wrapper",
}

TOOL_META["profile"] = "quick"


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
