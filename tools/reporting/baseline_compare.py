from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "baseline-compare",
    "name": "Baseline Compare",
    "category": "reporting",
    "summary": "Compare two baselines and summarise drift.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "baseline-compare/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
