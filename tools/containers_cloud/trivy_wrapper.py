from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "trivy-wrapper",
    "name": "Trivy Wrapper",
    "category": "containers_cloud",
    "summary": "Run trivy scan and parse top findings.",
    "risk": "low",
    "requires": ["trivy"],
    "supports_json": True,
    "default_output": "trivy-wrapper/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
