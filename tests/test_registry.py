from cyberkit.registry import discover_tools


def test_registry_discovers_tools() -> None:
    tools = discover_tools(refresh=True)
    assert len(tools) >= 90


def test_registry_tool_ids_unique() -> None:
    tools = discover_tools(refresh=True)
    tool_ids = [tool.tool_id for tool in tools]
    assert len(tool_ids) == len(set(tool_ids))


def test_at_least_40_full_handlers() -> None:
    tools = discover_tools(refresh=True)
    full = [tool for tool in tools if tool.meta.get("handler") != "stub"]
    assert len(full) >= 40
