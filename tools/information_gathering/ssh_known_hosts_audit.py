from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "ssh-known-hosts-audit",
    "name": "SSH Known Hosts Audit",
    "category": "information_gathering",
    "summary": "Parse known_hosts and flag weak/duplicate entries.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "ssh-known-hosts-audit/result.json",
    "handler": "ssh_known_hosts_audit",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
