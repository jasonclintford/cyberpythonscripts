from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "content-discovery-lite",
    "name": "Content Discovery Lite",
    "category": "web_audit",
    "summary": "Safe, rate-limited path discovery.",
    "risk": "medium",
    "requires": [],
    "supports_json": True,
    "default_output": "content-discovery-lite/result.json",
    "handler": "content_discovery_lite",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
