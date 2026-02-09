from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "ssh-config-audit",
    "name": "SSH Config Audit",
    "category": "host_hardening",
    "summary": "Audit sshd_config for insecure options.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "ssh-config-audit/result.json",
    "handler": "ssh_config_audit",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
