from __future__ import annotations

from collections.abc import Iterable

from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

SAFETY_NOTICE = "Use only on systems you own or have explicit permission to test."


def banner_panel() -> Panel:
    return Panel.fit(
        "[title]CyberKit[/title]\n[muted]Defensive security and authorised assessment toolkit[/muted]",
        title="[accent]CLI[/accent]",
        border_style="accent",
    )


def safety_panel() -> Panel:
    return Panel(
        f"[warning]{SAFETY_NOTICE}[/warning]",
        title="Safety",
        border_style="warning",
    )


def tools_table(rows: Iterable[dict[str, str]]) -> Table:
    table = Table(show_header=True, header_style="accent")
    table.add_column("ID", style="bright_white")
    table.add_column("Name", style="cyan")
    table.add_column("Risk", style="yellow")
    table.add_column("Requires", style="magenta")
    table.add_column("Summary", style="white")
    for row in rows:
        table.add_row(
            row.get("id", ""),
            row.get("name", ""),
            row.get("risk", ""),
            row.get("requires", ""),
            row.get("summary", ""),
        )
    return table


def category_tree(grouped: dict[str, list[str]]) -> Tree:
    root = Tree("[accent]Categories[/accent]")
    for category in sorted(grouped):
        branch = root.add(f"[title]{category}[/title]")
        for tool_id in sorted(grouped[category]):
            branch.add(tool_id)
    return root
