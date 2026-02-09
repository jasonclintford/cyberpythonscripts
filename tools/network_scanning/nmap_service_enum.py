from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "nmap-service-enum",
    "name": "Nmap Service Enum",
    "category": "network_scanning",
    "summary": "Service/version enumeration with controlled timing.",
    "risk": "medium",
    "requires": ["nmap"],
    "supports_json": True,
    "default_output": "nmap-service-enum/result.json",
    "handler": "nmap_wrapper",
}

TOOL_META["profile"] = "service"


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
