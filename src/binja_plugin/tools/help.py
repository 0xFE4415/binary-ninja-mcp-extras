"""Self-description of the plugin's tools, served from the mcp tool registry."""

from __future__ import annotations

import importlib
from typing import TypedDict

from binaryninja import mcp

from binja_plugin.tools import _show_nul

_TOOL_PREFIX = "rex_"
_NATIVE_TOOL_NAMES = frozenset({"rx_data_find", "rx_multi_find"})
_NATIVE_TOOL_CATEGORY = "scanning"

_UNCATEGORIZED = "other"
_UNCATEGORIZED_USE_WHEN = "Registered rex_ tools that no category module defines."

_CATEGORY_USE_WHEN: dict[str, str] = {
    "decompile": "bn_binary_triage gives the entry point; read its HLIL or disassembly, grep HLIL.",
    "strings": "Locate detected strings and the code that references them.",
    "scanning": "Find a magic constant or byte pattern, and the functions that contain it.",
    "data": "Read mapped bytes, relocations, or list references to an address.",
    "functions": "Define missing functions (code after int3, indirect targets), map call paths.",
    "dataflow": "Decide what a branch compares: constraints, HLIL statements, MLIL uses.",
    "uidf": "Pin values the decompiler cannot know so obfuscated arithmetic and byte checks fold.",
    "types": "Recover structs from access patterns, import or export type libraries.",
    "annotations": "Record conclusions: batch renames, comments, and types.",
    "components": "Group functions into named components.",
    "state": "Scratch key-values, tags, a markdown report, and undo/redo of a batch.",
    "exports": "Write full disassembly or symbol sweeps to a file instead of the response.",
    "analysis": "Wait for background analysis, or close the binary.",
    "escape": "Last resort when no tool fits: run Python, write memory. Report the gap afterward.",
    "help": "Discover the toolbox.",
}

_SCHEMA_BOUNDS = (
    "minimum",
    "maximum",
    "default",
    "enum",
    "minLength",
    "maxLength",
    "items",
    "minItems",
    "maxItems",
)


class _ToolSummary(TypedDict):
    name: str
    description: str


class _CategoryView(TypedDict):
    category: str
    use_when: str
    tools: list[_ToolSummary]


class _CategorySummary(TypedDict):
    name: str
    use_when: str
    tools: list[str]


class _CategoriesView(TypedDict):
    categories: list[_CategorySummary]


class _ToolView(TypedDict):
    name: str
    description: str
    parameters: list[dict[str, object]]


def _tools_by_category(registered: dict[str, mcp.Tool]) -> dict[str, list[str]]:
    categories: dict[str, list[str]] = {}
    for module_name in _CATEGORY_USE_WHEN:
        module = importlib.import_module(f"binja_plugin.tools.{module_name}")
        categories[module_name] = sorted(
            name
            for name, member in vars(module).items()
            if name in registered and member.__module__ == module.__name__
        )
    native_names = (name for name in registered if not name.startswith(_TOOL_PREFIX))
    categories[_NATIVE_TOOL_CATEGORY] = sorted([*categories[_NATIVE_TOOL_CATEGORY], *native_names])
    categorized: set[str] = set()
    for names in categories.values():
        categorized.update(names)
    categories[_UNCATEGORIZED] = sorted(set(registered) - categorized)
    return categories


def _category_view(registered: dict[str, mcp.Tool], category: str) -> _CategoryView:
    if category not in _CATEGORY_USE_WHEN and category != _UNCATEGORIZED:
        raise mcp.ToolError(
            "unknown_category",
            f"no category named '{_show_nul(category)}'; categories: "
            f"{', '.join([*_CATEGORY_USE_WHEN, _UNCATEGORIZED])}",
        )
    return {
        "category": category,
        "use_when": _CATEGORY_USE_WHEN.get(category, _UNCATEGORIZED_USE_WHEN),
        "tools": [
            {"name": name, "description": registered[name].description}
            for name in _tools_by_category(registered)[category]
        ],
    }


def _categories_view(registered: dict[str, mcp.Tool]) -> _CategoriesView:
    categories = _tools_by_category(registered)
    use_when_by_category = {**_CATEGORY_USE_WHEN, _UNCATEGORIZED: _UNCATEGORIZED_USE_WHEN}
    views: list[_CategorySummary] = []
    for name, names in categories.items():
        if names or name != _UNCATEGORIZED:
            views.append({"name": name, "use_when": use_when_by_category[name], "tools": names})
    return {"categories": views}


def _tool_view(registered: dict[str, mcp.Tool], tool_name: str) -> _ToolView:
    tool = registered.get(tool_name)
    if tool is None:
        raise mcp.ToolError(
            "unknown_tool",
            f"no tool named '{_show_nul(tool_name)}'; "
            f"registered tools: {', '.join(sorted(registered))}",
        )
    schema = tool.input_schema
    required = schema.get("required", [])
    parameters: list[dict[str, object]] = []
    for parameter_name, parameter_schema in schema.get("properties", {}).items():
        parameter: dict[str, object] = {
            "name": parameter_name,
            "type": parameter_schema.get("type"),
            "required": parameter_name in required,
            "description": parameter_schema.get("description", ""),
        }
        for bound in _SCHEMA_BOUNDS:
            if bound in parameter_schema:
                parameter[bound] = parameter_schema[bound]
        parameters.append(parameter)
    return {"name": tool_name, "description": tool.description, "parameters": parameters}


@mcp.tool(read_only=True, scope=mcp.McpToolScope.GlobalScope)
def rex_help(
    call: mcp.ToolCall, tool_name: str = "", category: str = ""
) -> _CategoryView | _CategoriesView | _ToolView:
    """Describe the rex_ tools, and rx_ tools if present, from the registry.

    :param tool_name: Tool whose parameters to describe; empty selects the category views.
    :param category: Category whose tools to list with purposes; empty lists the categories.
    """
    registered = {
        tool.name: tool
        for tool in mcp.Tool.list()
        if tool.name.startswith(_TOOL_PREFIX) or tool.name in _NATIVE_TOOL_NAMES
    }
    if tool_name and category:
        raise mcp.ToolError("invalid_params", "pass either tool_name or category, not both")
    if category:
        return _category_view(registered, category)
    if not tool_name:
        return _categories_view(registered)
    return _tool_view(registered, tool_name)
