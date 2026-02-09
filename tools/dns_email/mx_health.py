from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "mx-health",
    "name": "MX Health",
    "category": "dns_email",
    "summary": "Check MX resolution, port 25 reachability, and STARTTLS hint.",
    "risk": "medium",
    "requires": ["dig"],
    "supports_json": True,
    "default_output": "mx-health/result.json",
    "handler": "mx_health",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
