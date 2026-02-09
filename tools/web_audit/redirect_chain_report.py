from __future__ import annotations

from cyberkit.tool_impl import execute

TOOL_META = {
    "id": "redirect-chain-report",
    "name": "Redirect Chain Report",
    "category": "web_audit",
    "summary": "Show redirect hops and final destination.",
    "risk": "low",
    "requires": [],
    "supports_json": True,
    "default_output": "redirect-chain-report/result.json",
    "handler": "redirect_chain_report",
}


def main(argv: list[str] | None = None) -> int:
    return execute(TOOL_META, argv)


if __name__ == "__main__":
    raise SystemExit(main())
