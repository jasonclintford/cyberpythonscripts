from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "ssh-key-audit",
    "name": "SSH Key Audit",
    "category": "crypto_pki",
    "summary": "Audit SSH key type, size, and permissions.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "ssh-key-audit/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
