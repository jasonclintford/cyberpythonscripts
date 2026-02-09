from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "docker-socket-risk",
    "name": "Docker Socket Risk",
    "category": "containers_cloud",
    "summary": "Detect docker socket exposure and group risk.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "docker-socket-risk/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
