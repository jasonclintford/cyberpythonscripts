from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "report-html",
    "name": "Report HTML",
    "category": "reporting",
    "summary": "Generate simple HTML report from run artifacts.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "report-html/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
