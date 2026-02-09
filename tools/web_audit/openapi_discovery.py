from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "openapi-discovery",
    "name": "OpenAPI Discovery",
    "category": "web_audit",
    "summary": "Discover likely OpenAPI/Swagger endpoints.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "openapi-discovery/result.json",
    "handler": "openapi_discovery",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
