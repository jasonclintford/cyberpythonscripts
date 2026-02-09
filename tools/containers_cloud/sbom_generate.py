from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "sbom-generate",
    "name": "SBOM Generate",
    "category": "containers_cloud",
    "summary": "Generate SBOM using syft when available.",
    "risk": "low",
    "requires": ["syft"],
    "supports_json": True,
    "default_output": "sbom-generate/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
