from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "jwt-inspect",
    "name": "JWT Inspect",
    "category": "crypto_pki",
    "summary": "Decode JWT header/payload and flag weak patterns.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "jwt-inspect/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
