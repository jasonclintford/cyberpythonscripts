from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "suid-sgid-finder",
    "name": "SUID SGID Finder",
    "category": "host_hardening",
    "summary": "List SUID/SGID binaries and compare with baseline.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "suid-sgid-finder/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
