from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "pgp-key-inventory",
    "name": "PGP Key Inventory",
    "category": "crypto_pki",
    "summary": "List GPG keys, expiry, trust, and fingerprints.",
    "risk": "low",
    "requires": ["gpg"],
    "supports_json": True,
    "default_output": "pgp-key-inventory/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
