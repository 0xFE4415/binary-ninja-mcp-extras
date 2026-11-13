from __future__ import annotations

import inspect

from helpers import REGISTERED_TOOLS

EXPECTED_NAMES = sorted(
    [
        "rex_analysis_wait",
        "rex_annotate_many",
        "rex_binary_close",
        "rex_call_paths",
        "rex_component_add_functions",
        "rex_component_create",
        "rex_component_get",
        "rex_constant_find",
        "rex_data_find",
        "rex_data_read",
        "rex_decompile_many",
        "rex_string_refs",
        "rex_disasm_at",
        "rex_disasm_many",
        "rex_eval_python",
        "rex_eval_result",
        "rex_export_disasm",
        "rex_export_symbols",
        "rex_find_functions_by_pattern",
        "rex_function_constraints",
        "rex_function_containing",
        "rex_function_define",
        "rex_function_define_many",
        "rex_function_undefine",
        "rex_help",
        "rex_hlil_grep",
        "rex_hlil_statements",
        "rex_kv_delete",
        "rex_kv_get",
        "rex_kv_list",
        "rex_kv_set",
        "rex_memory_write",
        "rex_mlil_uses",
        "rex_parameter_variables",
        "rex_relocation_at",
        "rex_redo",
        "rex_report_show",
        "rex_string_read_at",
        "rex_string_search",
        "rex_struct_from_access",
        "rex_tag_list",
        "rex_tag_set",
        "rex_type_library_export",
        "rex_type_library_import",
        "rex_uidf_clear",
        "rex_uidf_list",
        "rex_uidf_set",
        "rex_uidf_set_many",
        "rex_undo",
        "rex_xrefs_to",
    ]
)

ALLOWED_OPTIONS = {
    "title",
    "scope",
    "read_only",
    "destructive",
    "idempotent",
    "open_world",
    "output_schema",
}

# The only approval-policy signal an agent gets is these two markings, so every tool
# must carry exactly one of them and the choice must be pinned per tool: a tool marked
# neither (the decorator's neutral default) looks safe to an approval policy no matter
# what it writes. Adding or renaming a tool updates this map in the same change.
EXPECTED_MARKINGS: dict[str, dict[str, bool]] = {
    "rex_analysis_wait": {"read_only": True, "destructive": False},
    "rex_annotate_many": {"read_only": False, "destructive": True},
    "rex_binary_close": {"read_only": False, "destructive": True},
    "rex_call_paths": {"read_only": True, "destructive": False},
    "rex_component_add_functions": {"read_only": False, "destructive": True},
    "rex_component_create": {"read_only": False, "destructive": True},
    "rex_component_get": {"read_only": True, "destructive": False},
    "rex_constant_find": {"read_only": True, "destructive": False},
    "rex_data_find": {"read_only": True, "destructive": False},
    "rex_data_read": {"read_only": True, "destructive": False},
    "rex_decompile_many": {"read_only": True, "destructive": False},
    "rex_string_refs": {"read_only": True, "destructive": False},
    "rex_disasm_at": {"read_only": True, "destructive": False},
    "rex_disasm_many": {"read_only": True, "destructive": False},
    "rex_eval_python": {"read_only": False, "destructive": True},
    "rex_eval_result": {"read_only": True, "destructive": False},
    "rex_export_disasm": {"read_only": False, "destructive": True},
    "rex_export_symbols": {"read_only": False, "destructive": True},
    "rex_find_functions_by_pattern": {"read_only": True, "destructive": False},
    "rex_function_constraints": {"read_only": True, "destructive": False},
    "rex_function_containing": {"read_only": True, "destructive": False},
    "rex_function_define": {"read_only": False, "destructive": True},
    "rex_function_define_many": {"read_only": False, "destructive": True},
    "rex_function_undefine": {"read_only": False, "destructive": True},
    "rex_help": {"read_only": True, "destructive": False},
    "rex_hlil_grep": {"read_only": True, "destructive": False},
    "rex_hlil_statements": {"read_only": True, "destructive": False},
    "rex_kv_delete": {"read_only": False, "destructive": True},
    "rex_kv_get": {"read_only": True, "destructive": False},
    "rex_kv_list": {"read_only": True, "destructive": False},
    "rex_kv_set": {"read_only": False, "destructive": True},
    "rex_memory_write": {"read_only": False, "destructive": True},
    "rex_mlil_uses": {"read_only": True, "destructive": False},
    "rex_parameter_variables": {"read_only": True, "destructive": False},
    "rex_relocation_at": {"read_only": True, "destructive": False},
    "rex_redo": {"read_only": False, "destructive": True},
    "rex_report_show": {"read_only": True, "destructive": False},
    "rex_string_read_at": {"read_only": True, "destructive": False},
    "rex_string_search": {"read_only": True, "destructive": False},
    "rex_struct_from_access": {"read_only": False, "destructive": True},
    "rex_tag_list": {"read_only": True, "destructive": False},
    "rex_tag_set": {"read_only": False, "destructive": True},
    "rex_type_library_export": {"read_only": False, "destructive": True},
    "rex_type_library_import": {"read_only": False, "destructive": True},
    "rex_uidf_clear": {"read_only": False, "destructive": True},
    "rex_uidf_list": {"read_only": True, "destructive": False},
    "rex_uidf_set": {"read_only": False, "destructive": True},
    "rex_uidf_set_many": {"read_only": False, "destructive": True},
    "rex_undo": {"read_only": False, "destructive": True},
    "rex_xrefs_to": {"read_only": True, "destructive": False},
}


def test_all_tools_are_registered_once() -> None:
    names = [name for name, _, _ in REGISTERED_TOOLS]
    assert sorted(names) == EXPECTED_NAMES
    assert len(names) == len(set(names))


def test_tool_names_are_namespaced() -> None:
    for name, _, _ in REGISTERED_TOOLS:
        assert name.startswith("rex_")
        assert not name.startswith("bn_")


def test_tool_docstrings_stay_stripped() -> None:
    for name, _, function in REGISTERED_TOOLS:
        docstring = inspect.cleandoc(function.__doc__ or "")
        lines = docstring.splitlines()
        # The bundled mcp layer serves the leading paragraph as the tool description and
        # nothing else: the description stays one physical line and nothing but the
        # :param: block may follow it.
        assert lines and lines[0] and not lines[0].startswith(":param "), (
            f"{name} needs a one-line description"
        )
        assert all(line == "" or line.startswith(":param ") for line in lines[1:]), (
            f"{name} carries docstring prose no client is served"
        )
        parameters = list(inspect.signature(function).parameters)
        assert parameters[0] == "call"
        for parameter in parameters[1:]:
            matching = [line for line in lines if line.startswith(f":param {parameter}:")]
            assert len(matching) == 1, f"{name} documents '{parameter}' not exactly once"
            # A bare marker is not just unserved prose: the mcp layer's parser glues the
            # following line into this parameter's description, so the fragment must be
            # on the marker line itself.
            assert matching[0] != f":param {parameter}:", (
                f"{name} leaves '{parameter}' without a description fragment"
            )


def test_tool_options_are_supported_by_the_decorator() -> None:
    for name, options, _ in REGISTERED_TOOLS:
        assert set(options) <= ALLOWED_OPTIONS, f"{name} passes unknown options {set(options)}"


def test_every_tool_has_a_pinned_marking() -> None:
    names = {name for name, _, _ in REGISTERED_TOOLS}
    # The map itself must cover every registered tool, so an added or renamed tool
    # cannot slip through unmarked.
    assert names == set(EXPECTED_MARKINGS)
    for name, options, _ in REGISTERED_TOOLS:
        expected = EXPECTED_MARKINGS[name]
        for marking in ("read_only", "destructive"):
            actual = options.get(marking, False)
            assert actual is expected[marking], (
                f"{name} marks {marking}={actual!r}, expected {expected[marking]}"
            )
