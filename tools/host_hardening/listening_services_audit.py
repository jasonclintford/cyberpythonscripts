from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "listening-services-audit",
    "name": "Listening Services Audit",
    "category": "host_hardening",
    "summary": "Summarise listening ports and owning processes.",
    "risk": "low",
    "requires": ["ss"],
    "supports_json": True,
    "default_output": "listening-services-audit/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
