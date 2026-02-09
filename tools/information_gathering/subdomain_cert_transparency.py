from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "subdomain-cert-transparency",
    "name": "Subdomain Cert Transparency",
    "category": "information_gathering",
    "summary": "Query certificate transparency logs for subdomain hints.",
    "risk": "medium",
    "requires": [],
    "supports_json": True,
    "default_output": "subdomain-cert-transparency/result.json",
    "handler": "subdomain_cert_transparency",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
