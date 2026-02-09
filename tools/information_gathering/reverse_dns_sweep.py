from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "reverse-dns-sweep",
    "name": "Reverse DNS Sweep",
    "category": "information_gathering",
    "summary": "Reverse lookup for IP list or CIDR with rate limiting.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "reverse-dns-sweep/result.json",
    "handler": "reverse_dns_sweep",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
