from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "web-tech-fingerprint",
    "name": "Web Tech Fingerprint",
    "category": "web_audit",
    "summary": "Basic fingerprint from headers and HTML markers.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "web-tech-fingerprint/result.json",
    "handler": "web_tech_fingerprint",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
