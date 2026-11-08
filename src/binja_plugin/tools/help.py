"""Self-description of the plugin's tools, served from the mcp tool registry."""

from __future__ import annotations

import importlib

from binaryninja import mcp

_TOOL_PREFIX = "rex_"

_UNCATEGORIZED = "other"
_UNCATEGORIZED_USE_WHEN = "Registered rex_ tools that no category module defines."

_CATEGORY_USE_WHEN: dict[str, str] = {
    "decompile": "First contact and reading code: entry point, main, HLIL/disassembly, HLIL grep.",
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

# Error codes the handlers define per parameter, beyond the schema checks the mcp layer
# applies before a handler runs. The registry records only the JSON Schema, not these —
# they live in the handler bodies — so the map is maintained by hand and pinned against
# the handler sources by tests/test_tools/test_help.py.
_PARAMETER_ERROR_CODES: dict[tuple[str, str], tuple[str, ...]] = {
    ("rex_call_paths", "from_addr"): ("no_function", "analysis_pending"),
    ("rex_call_paths", "to_addr"): ("no_function", "analysis_pending"),
    ("rex_component_add_functions", "path"): ("component_not_found",),
    ("rex_component_create", "name"): ("name_too_large",),
    ("rex_component_create", "parent_path"): ("component_not_found",),
    ("rex_component_get", "path"): ("component_not_found",),
    ("rex_data_find", "pattern"): ("pattern_too_large", "invalid_pattern"),
    ("rex_data_find", "section"): ("section_not_found",),
    ("rex_decompile_many", "functions"): ("analysis_pending",),
    ("rex_disasm_at", "address"): ("analysis_pending",),
    ("rex_eval_result", "key"): ("not_found",),
    ("rex_export_disasm", "address"): ("analysis_pending",),
    ("rex_export_disasm", "filename"): ("path_escape", "export_failed"),
    ("rex_export_symbols", "filename"): ("path_escape", "export_failed"),
    ("rex_find_functions_by_pattern", "pattern"): ("pattern_too_large", "invalid_pattern"),
    ("rex_function_constraints", "function"): ("no_mlil",),
    ("rex_function_containing", "addr"): ("no_function",),
    ("rex_function_define", "start"): ("define_failed",),
    ("rex_function_define_many", "addresses"): ("define_failed",),
    ("rex_function_undefine", "start"): ("no_function", "analysis_pending"),
    ("rex_hlil_grep", "regex"): ("invalid_regex",),
    ("rex_hlil_statements", "function"): ("no_hlil",),
    ("rex_mlil_uses", "address"): ("no_definition",),
    ("rex_mlil_uses", "function"): ("no_mlil",),
    ("rex_parameter_variables", "function"): ("no_mlil",),
    ("rex_parameter_variables", "parameter"): ("no_variable",),
    ("rex_kv_delete", "key"): ("invalid_key",),
    ("rex_kv_get", "key"): ("invalid_key", "not_found"),
    ("rex_kv_set", "key"): ("invalid_key", "key_too_large"),
    ("rex_kv_set", "value"): ("value_too_large",),
    ("rex_memory_write", "hex_data"): ("invalid_hex",),
    ("rex_report_show", "markdown"): ("content_too_large",),
    ("rex_report_show", "title"): ("title_too_large",),
    ("rex_string_read_at", "addr"): ("no_string",),
    ("rex_string_search", "section"): ("section_not_found",),
    ("rex_struct_from_access", "name"): ("name_too_large",),
    ("rex_tag_set", "data"): ("data_too_large",),
    ("rex_tag_set", "tag_type"): ("tag_type_not_found", "tag_type_too_large"),
    ("rex_type_library_export", "filename"): ("path_escape", "export_failed"),
    ("rex_type_library_export", "library_name"): ("library_name_too_large",),
    ("rex_type_library_import", "path"): ("library_not_found",),
    ("rex_uidf_clear", "variable"): ("no_mlil", "no_variable"),
    ("rex_uidf_set", "def_address"): ("definition_not_found",),
    ("rex_uidf_set", "variable"): ("no_mlil", "no_variable", "ambiguous_definition"),
}


def _tools_by_category(registered: dict[str, mcp.Tool]) -> dict[str, list[str]]:
    categories: dict[str, list[str]] = {}
    for module_name in _CATEGORY_USE_WHEN:
        module = importlib.import_module(f"binja_plugin.tools.{module_name}")
        categories[module_name] = sorted(
            name
            for name, member in vars(module).items()
            if name in registered and member.__module__ == module.__name__
        )
    categorized = {name for names in categories.values() for name in names}
    categories[_UNCATEGORIZED] = sorted(set(registered) - categorized)
    return categories


@mcp.tool(read_only=True)
def rex_help(call: mcp.ToolCall, tool_name: str = "", category: str = "") -> dict[str, object]:
    """Describe the plugin's rex_ tools from the mcp registry.

    :param tool_name: rex_ tool whose parameters to describe; empty selects the category views.
    :param category: Category whose tools to list with purposes; empty lists the categories.
    """
    registered = {tool.name: tool for tool in mcp.Tool.list() if tool.name.startswith(_TOOL_PREFIX)}
    if tool_name and category:
        raise mcp.ToolError("invalid_params", "pass either tool_name or category, not both")
    if category:
        if category not in _CATEGORY_USE_WHEN and category != _UNCATEGORIZED:
            raise mcp.ToolError(
                "unknown_category",
                f"no category named '{category}'; categories: "
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
    if not tool_name:
        categories = _tools_by_category(registered)
        use_when_by_category = {**_CATEGORY_USE_WHEN, _UNCATEGORIZED: _UNCATEGORIZED_USE_WHEN}
        return {
            "categories": [
                {"name": name, "use_when": use_when_by_category[name], "tools": names}
                for name, names in categories.items()
                if names or name != _UNCATEGORIZED
            ]
        }
    tool = registered.get(tool_name)
    if tool is None:
        raise mcp.ToolError(
            "unknown_tool",
            "no rex_ tool named "
            f"'{tool_name}'; registered rex_ tools: {', '.join(sorted(registered))}",
        )
    schema = tool.input_schema
    required = schema.get("required", [])
    parameters = []
    for parameter_name, parameter_schema in schema["properties"].items():
        parameter: dict[str, object] = {
            "name": parameter_name,
            "type": parameter_schema["type"],
            "required": parameter_name in required,
            "description": parameter_schema["description"],
            "error_codes": list(_PARAMETER_ERROR_CODES.get((tool_name, parameter_name), ())),
        }
        for bound in (
            "minimum",
            "maximum",
            "default",
            "enum",
            "minLength",
            "maxLength",
            "items",
        ):
            if bound in parameter_schema:
                parameter[bound] = parameter_schema[bound]
        parameters.append(parameter)
    return {"name": tool_name, "description": tool.description, "parameters": parameters}
