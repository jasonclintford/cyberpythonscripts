from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "tls-cert-inspect",
    "name": "TLS Cert Inspect",
    "category": "web_audit",
    "summary": "Inspect certificate expiry/SAN/key details.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "tls-cert-inspect/result.json",
    "handler": "tls_cert_inspect",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
