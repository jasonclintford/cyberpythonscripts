from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "public-ip",
    "name": "Public IP",
    "category": "misc",
    "summary": "Fetch public IP from a simple endpoint.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "public-ip/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
