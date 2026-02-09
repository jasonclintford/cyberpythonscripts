from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "host-resolve",
    "name": "Host Resolve",
    "category": "information_gathering",
    "summary": "Resolve A/AAAA records for hostnames.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "host-resolve/result.json",
    "handler": "host_resolve",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
