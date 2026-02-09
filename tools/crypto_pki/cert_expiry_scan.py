from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "cert-expiry-scan",
    "name": "Cert Expiry Scan",
    "category": "crypto_pki",
    "summary": "Check certificate expiry windows across hosts.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "cert-expiry-scan/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
