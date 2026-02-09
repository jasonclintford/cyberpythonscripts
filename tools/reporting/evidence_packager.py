from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "evidence-packager",
    "name": "Evidence Packager",
    "category": "reporting",
    "summary": "Zip case folder with manifest and checksums.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "evidence-packager/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
