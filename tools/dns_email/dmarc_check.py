from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "dmarc-check",
    "name": "DMARC Check",
    "category": "dns_email",
    "summary": "Parse DMARC policy and report tags.",
    "risk": "low",
    "requires": ["dig"],
    "supports_json": True,
    "default_output": "dmarc-check/result.json",
    "handler": "dmarc_check",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
