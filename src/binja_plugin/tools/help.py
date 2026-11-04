"""Self-description of the plugin's tools, served from the mcp tool registry."""

from __future__ import annotations

from binaryninja import mcp

_TOOL_PREFIX = "rex_"

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
    ("rex_disasm_many", "addresses"): ("analysis_pending",),
    ("rex_eval_result", "key"): ("not_found",),
    ("rex_export_disasm", "address"): ("analysis_pending",),
    ("rex_export_disasm", "filename"): ("path_escape", "export_failed"),
    ("rex_export_symbols", "filename"): ("path_escape", "export_failed"),
    ("rex_find_functions_by_pattern", "pattern"): ("pattern_too_large", "invalid_pattern"),
    ("rex_function_containing", "addr"): ("no_function",),
    ("rex_function_define", "start"): ("define_failed",),
    ("rex_function_define_many", "addresses"): ("define_failed",),
    ("rex_function_undefine", "start"): ("no_function",),
    ("rex_hlil_grep", "regex"): ("invalid_regex",),
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
}


@mcp.tool(read_only=True)
def rex_help(call: mcp.ToolCall, tool_name: str = "") -> dict[str, object]:
    """Describe the plugin's rex_ tools from the mcp registry.

    :param tool_name: rex_ tool to describe; empty lists every rex_ tool's name and purpose.
    """
    registered = {tool.name: tool for tool in mcp.Tool.list() if tool.name.startswith(_TOOL_PREFIX)}
    if not tool_name:
        return {
            "tools": [
                {"name": name, "description": registered[name].description}
                for name in sorted(registered)
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
        for bound in ("minimum", "maximum", "default", "enum", "minLength", "items"):
            if bound in parameter_schema:
                parameter[bound] = parameter_schema[bound]
        parameters.append(parameter)
    return {"name": tool_name, "description": tool.description, "parameters": parameters}
