from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "report-init",
    "name": "Report Init",
    "category": "reporting",
    "summary": "Create case folder with metadata and notes template.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "report-init/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
