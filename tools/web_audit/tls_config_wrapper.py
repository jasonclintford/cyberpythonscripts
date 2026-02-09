from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "tls-config-wrapper",
    "name": "TLS Config Wrapper",
    "category": "web_audit",
    "summary": "Wrapper around sslscan/testssl with parsed findings.",
    "risk": "medium",
    "requires": ["sslscan"],
    "supports_json": True,
    "default_output": "tls-config-wrapper/result.json",
    "handler": "tls_config_wrapper",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
