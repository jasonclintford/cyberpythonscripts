from __future__ import annotations

import os
import platform
import shlex
import sys
from pathlib import Path

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from cyberkit.core.io import read_json, write_text
from cyberkit.core.reporting import find_run
from cyberkit.core.toolcheck import is_installed, probe_version
from cyberkit.registry import (
    by_id,
    dependency_set,
    discover_tools,
    filter_records,
    grouped_by_category,
    search,
)
from cyberkit.ui.console import console
from cyberkit.ui.renderers import (
    SAFETY_NOTICE,
    banner_panel,
    category_tree,
    safety_panel,
    tools_table,
)

app = typer.Typer(add_completion=False, help=f"{SAFETY_NOTICE}")
report_app = typer.Typer(help=f"{SAFETY_NOTICE}")
app.add_typer(report_app, name="report")


def _records_to_rows(records: list) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for record in records:
        rows.append(
            {
                "id": record.tool_id,
                "name": str(record.meta.get("name", "")),
                "risk": str(record.meta.get("risk", "")),
                "requires": ", ".join(record.meta.get("requires", [])) or "-",
                "summary": str(record.meta.get("summary", "")),
            }
        )
    return rows


def _execute_tool(tool_id: str, args: list[str], json_output: bool = False) -> int:
    record = by_id(tool_id)
    if record is None:
        console.print(f"[danger]Unknown tool id:[/danger] {tool_id}")
        return 2

    supports_json = bool(record.meta.get("supports_json", False))
    if json_output:
        if not supports_json:
            console.print("[danger]This tool does not support JSON output.[/danger]")
            return 2
        if "--json" not in args:
            args = ["--json", *args]

    try:
        result = record.module.main(args)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1
    except Exception as exc:  # pragma: no cover - defensive runtime boundary
        console.print(f"[danger]Tool execution failed:[/danger] {exc}")
        return 1

    return int(result) if isinstance(result, int) else 0


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    console.print(banner_panel())
    console.print(safety_panel())
    if ctx.invoked_subcommand is None:
        console.print("Use `cyberkit --help` to see commands.")


@app.command("doctor", help=f"{SAFETY_NOTICE}")
def doctor() -> None:
    records = discover_tools()
    deps = sorted(dependency_set(records))

    env_table = Table(title="Environment", header_style="accent")
    env_table.add_column("Check")
    env_table.add_column("Value")
    env_table.add_row("Python", platform.python_version())
    env_table.add_row("OS", platform.platform())
    env_table.add_row("Python >= 3.10", "yes" if sys.version_info >= (3, 10) else "no")
    env_table.add_row(
        "EUID is root", "yes" if hasattr(os, "geteuid") and os.geteuid() == 0 else "no"
    )
    console.print(env_table)

    dep_table = Table(title="Dependency Matrix", header_style="accent")
    dep_table.add_column("Command")
    dep_table.add_column("Installed")
    dep_table.add_column("Version")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Checking external utilities...", total=len(deps) or 1)
        for dep in deps:
            installed = is_installed(dep)
            dep_table.add_row(
                dep, "yes" if installed else "no", probe_version(dep) if installed else "missing"
            )
            progress.advance(task, 1)

    console.print(dep_table)

    cap_table = Table(title="Tool Capability", header_style="accent")
    cap_table.add_column("Tool ID")
    cap_table.add_column("Ready")
    cap_table.add_column("Missing Requirements")
    for record in sorted(records, key=lambda r: r.tool_id):
        requires = record.meta.get("requires", [])
        missing = [dep for dep in requires if not is_installed(dep)]
        cap_table.add_row(record.tool_id, "yes" if not missing else "no", ", ".join(missing) or "-")
    console.print(cap_table)


@app.command("list", help=f"{SAFETY_NOTICE}")
def list_tools(
    category: str | None = typer.Option(None, "--category", help="Filter by category."),
    risk: str | None = typer.Option(None, "--risk", help="Filter by risk."),
) -> None:
    records = filter_records(category=category, risk=risk)
    grouped = grouped_by_category(records)
    console.print(
        category_tree({cat: [record.tool_id for record in recs] for cat, recs in grouped.items()})
    )
    console.print(tools_table(_records_to_rows(records)))


@app.command("search", help=f"{SAFETY_NOTICE}")
def search_tools(query: str = typer.Argument(..., help="Keyword to search.")) -> None:
    records = search(query)
    if not records:
        console.print("[warning]No matching tools found.[/warning]")
        raise typer.Exit(code=1)
    console.print(tools_table(_records_to_rows(records)))


@app.command(help=f"{SAFETY_NOTICE}")
def info(tool_id: str = typer.Argument(..., help="Tool id, for example nmap-quick.")) -> None:
    record = by_id(tool_id)
    if record is None:
        console.print(f"[danger]Unknown tool id:[/danger] {tool_id}")
        raise typer.Exit(code=2)

    meta = record.meta
    info_table = Table(title=f"Tool: {tool_id}", header_style="accent")
    info_table.add_column("Field")
    info_table.add_column("Value")
    info_table.add_row("Name", str(meta.get("name", "")))
    info_table.add_row("Category", str(meta.get("category", "")))
    info_table.add_row("Risk", str(meta.get("risk", "")))
    info_table.add_row("Requires", ", ".join(meta.get("requires", [])) or "-")
    info_table.add_row("Supports JSON", "yes" if meta.get("supports_json") else "no")
    info_table.add_row("Default output", str(meta.get("default_output", "")))
    info_table.add_row("Summary", str(meta.get("summary", "")))
    console.print(info_table)

    examples = meta.get("examples", [])
    if examples:
        console.print("Examples:")
        for example in examples:
            console.print(f"  - `{example}`")


@app.command(
    "run",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    help=f"{SAFETY_NOTICE}",
)
def run_tool(
    ctx: typer.Context,
    tool_id: str = typer.Argument(..., help="Tool id to execute."),
    json_output: bool = typer.Option(False, "--json", help="Ask tool to emit JSON when supported."),
) -> None:
    code = _execute_tool(tool_id, list(ctx.args), json_output=json_output)
    raise typer.Exit(code=code)


@app.command(help=f"{SAFETY_NOTICE}")
def browse() -> None:
    records = discover_tools()
    grouped = grouped_by_category(records)
    if not grouped:
        console.print("[danger]No tools discovered.[/danger]")
        raise typer.Exit(code=1)

    categories = sorted(grouped)
    console.print("[accent]Select a category:[/accent]")
    for idx, category in enumerate(categories, start=1):
        console.print(f"{idx}. {category}")
    category_idx = typer.prompt("Category number", type=int)
    if category_idx < 1 or category_idx > len(categories):
        console.print("[danger]Invalid category selection.[/danger]")
        raise typer.Exit(code=2)

    selected_category = categories[category_idx - 1]
    category_tools = grouped[selected_category]
    console.print(f"[accent]Select a tool from {selected_category}:[/accent]")
    for idx, record in enumerate(category_tools, start=1):
        console.print(f"{idx}. {record.tool_id} - {record.meta.get('summary', '')}")
    tool_idx = typer.prompt("Tool number", type=int)
    if tool_idx < 1 or tool_idx > len(category_tools):
        console.print("[danger]Invalid tool selection.[/danger]")
        raise typer.Exit(code=2)

    selected_tool = category_tools[tool_idx - 1]
    raw_args = typer.prompt("Arguments (optional)", default="")
    args = shlex.split(raw_args) if raw_args.strip() else []
    code = _execute_tool(selected_tool.tool_id, args, json_output=False)
    raise typer.Exit(code=code)


@report_app.command("open", help=f"{SAFETY_NOTICE}")
def report_open(
    run_id: str = typer.Argument(..., help="Run id, e.g. nmap-quick-20260101T000000Z"),
) -> None:
    run_dir = find_run(run_id)
    if run_dir is None:
        console.print(f"[danger]Run not found:[/danger] {run_id}")
        raise typer.Exit(code=1)
    run_json = run_dir / "run.json"
    if not run_json.exists():
        console.print(f"[danger]Invalid run directory:[/danger] {run_dir}")
        raise typer.Exit(code=1)
    payload = read_json(run_json)
    table = Table(title=f"Run: {payload.get('run_id', run_id)}", header_style="accent")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Tool", str(payload.get("tool_id", "")))
    table.add_row("Status", str(payload.get("status", "")))
    table.add_row("Started", str(payload.get("started_at", "")))
    table.add_row("Finished", str(payload.get("finished_at", "")))
    table.add_row("Directory", str(run_dir))
    table.add_row("Files", ", ".join(payload.get("result_files", [])) or "-")
    console.print(table)


@app.command("update-catalogue", help=f"{SAFETY_NOTICE}")
def update_catalogue() -> None:
    records = discover_tools(refresh=True)
    grouped = grouped_by_category(records)
    lines = [
        "# CyberKit Tool Catalogue",
        "",
        f"Total tools: **{len(records)}**",
        "",
    ]
    for category, items in grouped.items():
        lines.extend(
            [
                f"## {category}",
                "",
                "| id | name | risk | requires | summary |",
                "|---|---|---|---|---|",
            ]
        )
        for record in items:
            meta = record.meta
            requires = ", ".join(meta.get("requires", [])) or "-"
            lines.append(
                f"| `{record.tool_id}` | {meta.get('name', '')} | {meta.get('risk', '')} | {requires} | {meta.get('summary', '')} |"
            )
        lines.append("")

    output_path = Path("docs") / "tool-catalogue.md"
    write_text(output_path, "\n".join(lines))
    console.print(f"[ok]Updated catalogue:[/ok] {output_path}")


if __name__ == "__main__":
    app()
