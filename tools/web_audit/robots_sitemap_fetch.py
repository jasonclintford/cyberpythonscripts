from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "robots-sitemap-fetch",
    "name": "Robots Sitemap Fetch",
    "category": "web_audit",
    "summary": "Fetch robots.txt and sitemap URLs.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "robots-sitemap-fetch/result.json",
    "handler": "robots_sitemap_fetch",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
