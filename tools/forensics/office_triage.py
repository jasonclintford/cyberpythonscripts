from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "office-triage",
    "name": "Office Triage",
    "category": "forensics",
    "summary": "Safe office file triage with optional oletools.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "office-triage/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
