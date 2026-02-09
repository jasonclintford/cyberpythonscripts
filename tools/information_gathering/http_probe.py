from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "http-probe",
    "name": "HTTP Probe",
    "category": "information_gathering",
    "summary": "Probe URLs and capture status, redirects, and title.",
    "risk": "medium",
    "requires": [],
    "supports_json": True,
    "default_output": "http-probe/result.json",
    "handler": "http_probe",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
