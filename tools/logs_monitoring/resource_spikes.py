from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "resource-spikes",
    "name": "Resource Spikes",
    "category": "logs_monitoring",
    "summary": "Summarise CPU/memory spikes from telemetry.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "resource-spikes/result.json",
    "handler": "stub",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
