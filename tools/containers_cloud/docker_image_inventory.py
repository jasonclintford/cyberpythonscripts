from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "docker-image-inventory",
    "name": "Docker Image Inventory",
    "category": "containers_cloud",
    "summary": "List images, tags, dates, and sizes.",
    "risk": "low",
    "requires": ["docker"],
    "supports_json": True,
    "default_output": "docker-image-inventory/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
