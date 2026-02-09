from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "service-banner-grab",
    "name": "Service Banner Grab",
    "category": "information_gathering",
    "summary": "Safe TCP connect banner grab for selected ports.",
    "risk": "medium",
    "requires": [],
    "supports_json": True,
    "default_output": "service-banner-grab/result.json",
    "handler": "service_banner_grab",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
