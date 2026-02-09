from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "exif-extract",
    "name": "Exif Extract",
    "category": "forensics",
    "summary": "Extract metadata via exiftool fallback logic.",
    "risk": "low",
    "requires": ["exiftool"],
    "supports_json": True,
    "default_output": "exif-extract/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
