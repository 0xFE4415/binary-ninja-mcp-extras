from __future__ import annotations

import ast
import inspect
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from helpers import (
    REGISTERED_TOOLS,
    FakeParsingToolCall,
    FakeTool,
    FakeToolError,
    _call,
    _disasm_view,
    _use_export_root,
    get_tool,
)
from helpers_uidf import FakeMediumLevelIL, FakeVariable
from helpers_view import (
    FakeArchitecture,
    FakeBinaryView,
    FakeFunction,
    FakeType,
    RenderableText,
)

import binja_plugin
from binja_plugin.tools.help import (
    _CATEGORY_USE_WHEN,
    _PARAMETER_ERROR_CODES,
    _UNCATEGORIZED,
    _UNCATEGORIZED_USE_WHEN,
)
from binja_plugin.tools.scanning import _MAX_PATTERN_CHARS

# Error codes the handlers define for the tool as a whole — batch or view-level failures
# no single parameter owns, plus rex_help's own unknown-name rejection. The
# per-parameter table does not list these.
_TOOL_LEVEL_CODES = frozenset(
    {
        "annotate_failed",
        "clear_failed",
        "close_failed",
        "create_failed",
        "finalize_failed",
        "no_arch",
        "redo_failed",
        "set_failed",
        "undo_failed",
        "unknown_category",
        "unknown_tool",
    }
)

_MUTMUT_VARIANT = re.compile(r"__mutmut_\d+$")
_MUTMUT_ORIGINAL = re.compile(r"^x_(.+)__mutmut_orig$")


def _help(tool_name: str = "", category: str = "") -> Any:
    _, function = get_tool("rex_help")
    return function(_call(FakeBinaryView()), tool_name=tool_name, category=category)


def test_help_index_places_every_rex_tool_in_exactly_one_category() -> None:
    listed = [name for entry in _help()["categories"] for name in entry["tools"]]
    assert sorted(listed) == sorted(name for name, _, _ in REGISTERED_TOOLS)


def test_help_index_entries_carry_only_a_name_a_use_when_line_and_tool_names() -> None:
    entries = _help()["categories"]
    assert entries
    for entry in entries:
        assert set(entry) == {"name", "use_when", "tools"}
        assert entry["use_when"]
        assert all(isinstance(name, str) for name in entry["tools"])


def test_help_index_pins_every_use_when_line() -> None:
    assert {entry["name"]: entry["use_when"] for entry in _help()["categories"]} == {
        "decompile": (
            "First contact and reading code: entry point, main, HLIL/disassembly, HLIL grep."
        ),
        "strings": "Locate detected strings and the code that references them.",
        "scanning": "Find a magic constant or byte pattern, and the functions that contain it.",
        "data": "Read mapped bytes, relocations, or list references to an address.",
        "functions": (
            "Define missing functions (code after int3, indirect targets), map call paths."
        ),
        "dataflow": "Decide what a branch compares: constraints, HLIL statements, MLIL uses.",
        "uidf": (
            "Pin values the decompiler cannot know so obfuscated arithmetic and byte checks fold."
        ),
        "types": "Recover structs from access patterns, import or export type libraries.",
        "annotations": "Record conclusions: batch renames, comments, and types.",
        "components": "Group functions into named components.",
        "state": "Scratch key-values, tags, a markdown report, and undo/redo of a batch.",
        "exports": "Write full disassembly or symbol sweeps to a file instead of the response.",
        "analysis": "Wait for background analysis, or close the binary.",
        "escape": (
            "Last resort when no tool fits: run Python, write memory. Report the gap afterward."
        ),
        "help": "Discover the toolbox.",
    }


def test_help_index_keeps_a_category_whose_tools_are_all_unregistered() -> None:
    saved = list(REGISTERED_TOOLS)
    REGISTERED_TOOLS[:] = [entry for entry in saved if not entry[0].startswith("rex_uidf_")]
    try:
        entries = {entry["name"]: entry for entry in _help()["categories"]}
    finally:
        REGISTERED_TOOLS[:] = saved
    assert entries["uidf"]["tools"] == []


def test_help_index_places_the_uidf_tools_in_the_uidf_category() -> None:
    entries = {entry["name"]: entry for entry in _help()["categories"]}
    assert entries["uidf"]["tools"] == [
        "rex_uidf_clear",
        "rex_uidf_list",
        "rex_uidf_set",
        "rex_uidf_set_many",
    ]


def test_help_category_lists_its_tools_with_their_purposes() -> None:
    listing = _help(category="strings")
    assert listing["category"] == "strings"
    assert listing["use_when"] == "Locate detected strings and the code that references them."
    search = {tool["name"]: tool for tool in listing["tools"]}["rex_string_search"]
    assert search["description"] == (
        "Search the binary's detected strings by substring or regular expression."
    )
    assert [tool["name"] for tool in listing["tools"]] == [
        "rex_string_read_at",
        "rex_string_refs",
        "rex_string_search",
    ]


def test_help_lists_itself_in_the_help_category() -> None:
    assert {
        "name": "rex_help",
        "description": "Describe the plugin's rex_ tools from the mcp registry.",
    } in _help(category="help")["tools"]


def test_help_excludes_non_rex_registry_entries_from_the_index() -> None:
    def bn_builtin(call: object) -> dict[str, object]:
        """A stand-in for a built-in bn_ tool.

        :param call: The tool call.
        """
        return {}

    saved = list(REGISTERED_TOOLS)
    REGISTERED_TOOLS.append(("bn_builtin", {}, bn_builtin))
    try:
        listed = [name for entry in _help()["categories"] for name in entry["tools"]]
    finally:
        REGISTERED_TOOLS[:] = saved
    assert "bn_builtin" not in listed
    assert "rex_string_search" in listed


def _foreign_tool(call: object) -> dict[str, object]:
    """A stand-in for a rex_ tool that no category module defines.

    :param call: The tool call.
    """
    return {}


def test_help_lists_a_rex_tool_no_category_defines_under_other() -> None:
    saved = list(REGISTERED_TOOLS)
    REGISTERED_TOOLS.append(("rex_foreign", {}, _foreign_tool))
    try:
        entries = {entry["name"]: entry for entry in _help()["categories"]}
        listing = _help(category="other")
    finally:
        REGISTERED_TOOLS[:] = saved
    assert entries["other"]["tools"] == ["rex_foreign"]
    assert [tool["name"] for tool in listing["tools"]] == ["rex_foreign"]


def test_help_omits_other_from_the_index_when_every_tool_is_categorized() -> None:
    assert "other" not in [entry["name"] for entry in _help()["categories"]]
    assert _help(category="other")["tools"] == []


def test_help_lists_a_tool_imported_into_another_module_only_under_its_definer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys.modules["binja_plugin.tools.strings"],
        "rex_decompile_many",
        sys.modules["binja_plugin.tools.decompile"].rex_decompile_many,
        raising=False,
    )
    listed = [name for entry in _help()["categories"] for name in entry["tools"]]
    assert listed.count("rex_decompile_many") == 1
    assert "rex_decompile_many" in [tool["name"] for tool in _help(category="decompile")["tools"]]
    assert "rex_decompile_many" not in [tool["name"] for tool in _help(category="strings")["tools"]]


def test_help_fails_on_an_unknown_category_and_lists_the_valid_ones() -> None:
    with pytest.raises(FakeToolError) as exc:
        _help(category="nope")
    assert exc.value.code == "unknown_category"
    expected_categories = ", ".join([*_CATEGORY_USE_WHEN, _UNCATEGORIZED])
    assert exc.value.message == f"no category named 'nope'; categories: {expected_categories}"


@pytest.mark.parametrize("category", ["strings", "nope"])
def test_help_rejects_a_tool_name_together_with_any_category(category: str) -> None:
    with pytest.raises(FakeToolError) as exc:
        _help("rex_string_search", category=category)
    assert exc.value.code == "invalid_params"


def test_help_details_types_defaults_and_bounds() -> None:
    detail = _help("rex_string_search")
    assert detail["name"] == "rex_string_search"
    assert detail["description"] == (
        "Search the binary's detected strings by substring or regular expression."
    )
    by_name = {parameter["name"]: parameter for parameter in detail["parameters"]}
    assert by_name["pattern"] == {
        "name": "pattern",
        "type": "string",
        "required": False,
        "description": "Substring or regular expression to match; empty matches every string.",
        "error_codes": ["invalid_regex"],
        "default": "",
    }
    assert by_name["limit"] == {
        "name": "limit",
        "type": "integer",
        "required": False,
        "description": "Maximum strings to return.",
        "error_codes": [],
        "minimum": 0,
        "maximum": 500,
        "default": 50,
    }
    assert by_name["offset"]["minimum"] == 0
    assert "maximum" not in by_name["offset"]
    assert by_name["string_type"]["enum"] == [
        "AsciiString",
        "Utf16String",
        "Utf32String",
        "Utf8String",
    ]


def test_help_states_that_call_paths_defaults_to_callers_and_reachability_needs_callees() -> None:
    detail = _help("rex_call_paths")
    assert detail["description"] == (
        "Bounded BFS for call paths; direction defaults to callers, "
        'so "A reaches B?" needs callees.'
    )
    by_name = {parameter["name"]: parameter for parameter in detail["parameters"]}
    assert by_name["direction"]["default"] == "callers"
    assert by_name["direction"]["description"] == (
        'Default "callers": to_addr reaches from_addr; "callees": the reverse.'
    )


def test_help_details_required_flags_and_per_parameter_error_codes() -> None:
    by_name = {parameter["name"]: parameter for parameter in _help("rex_data_find")["parameters"]}
    assert by_name["pattern"]["required"] is True
    assert by_name["pattern"]["maxLength"] == _MAX_PATTERN_CHARS
    assert by_name["pattern"]["error_codes"] == ["pattern_too_large", "invalid_pattern"]
    assert by_name["section"]["error_codes"] == ["section_not_found"]
    assert by_name["limit"]["required"] is False


def test_help_details_the_annotate_items_schema() -> None:
    by_name = {
        parameter["name"]: parameter for parameter in _help("rex_annotate_many")["parameters"]
    }
    items = by_name["items"]
    assert items["type"] == "array"
    assert items["items"]["properties"]["addr"]["type"] == ["integer", "string"]
    assert items["items"]["required"] == ["addr"]


def test_help_details_the_uidf_batch_items_schema() -> None:
    by_name = {
        parameter["name"]: parameter for parameter in _help("rex_uidf_set_many")["parameters"]
    }
    items = by_name["items"]
    assert items["type"] == "array"
    assert items["items"]["required"] == ["variable", "value"]
    assert items["items"]["properties"]["def_address"]["type"] == ["integer", "string"]
    assert items["items"]["properties"]["state"]["enum"] == [
        "ConstantValue",
        "ConstantPointerValue",
        "StackFrameOffset",
        "SignedRangeValue",
        "UnsignedRangeValue",
        "InSetOfValues",
        "NotInSetOfValues",
    ]


def test_help_details_non_empty_strings_and_itself() -> None:
    by_name = {parameter["name"]: parameter for parameter in _help("rex_report_show")["parameters"]}
    assert by_name["title"]["minLength"] == 1
    assert by_name["title"]["error_codes"] == ["title_too_large"]

    own = {parameter["name"]: parameter for parameter in _help("rex_help")["parameters"]}
    assert own["tool_name"] == {
        "name": "tool_name",
        "type": "string",
        "required": False,
        "description": "rex_ tool whose parameters to describe; empty selects the category views.",
        "error_codes": [],
        "default": "",
    }
    assert own["category"] == {
        "name": "category",
        "type": "string",
        "required": False,
        "description": "Category whose tools to list with purposes; empty lists the categories.",
        "error_codes": [],
        "default": "",
    }


def test_help_fails_on_an_unknown_name_and_lists_the_valid_ones() -> None:
    with pytest.raises(FakeToolError) as exc:
        _help("rex_nope")
    assert exc.value.code == "unknown_tool"
    registered = ", ".join(sorted(tool.name for tool in FakeTool.list()))
    expected = f"no rex_ tool named 'rex_nope'; registered rex_ tools: {registered}"
    assert exc.value.message == expected


def test_help_uncategorized_category_reports_the_uncategorized_use_when() -> None:
    listing = _help(category="other")
    assert listing["use_when"] == _UNCATEGORIZED_USE_WHEN


def test_help_error_code_table_keys_are_registered_parameters() -> None:
    registered = {
        (tool.name, parameter_name)
        for tool in FakeTool.list()
        for parameter_name in tool.input_schema["properties"]
    }
    assert set(_PARAMETER_ERROR_CODES) <= registered


def _walk_definitions(node: ast.AST) -> Iterator[ast.AST]:
    # Under mutmut the package source carries every mutant inline as x__name__mutmut_N
    # copies whose literals are mutated; the pristine bodies live in __mutmut_orig. The
    # scan must read only the real code, so numbered variants are pruned (the pattern
    # never matches outside a mutants tree).
    for child in ast.iter_child_nodes(node):
        if (
            isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
            and _MUTMUT_VARIANT.search(child.name) is not None
        ):
            continue
        yield child
        yield from _walk_definitions(child)


def _defined_error_codes() -> set[str]:
    """Collect the error-code literals the package's handlers and shared helpers define.

    Covers the ToolError first arguments and the code arguments handed to the shared
    helpers that raise on a handler's behalf: _validate_text's too-large code and
    _require_containing_function's containment code.
    """
    code_positions = {
        "ToolError": 0,
        "_validate_text": 3,
        "_require_containing_function": 2,
        "_missing_il_error": 2,
    }
    codes: set[str] = set()
    for path in Path(binja_plugin.__file__).parent.rglob("*.py"):
        for node in _walk_definitions(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            if isinstance(target, ast.Attribute):
                name = target.attr
            elif isinstance(target, ast.Name):
                name = target.id
            else:
                continue
            position = code_positions.get(name)
            if position is not None and len(node.args) > position:
                argument = node.args[position]
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    codes.add(argument.value)
    return codes


# Tool-level codes a parameter lists anyway because a batch reports them per item, in-band.
_LISTED_TOOL_LEVEL_CODES = {"rex_uidf_set_many": {"set_failed"}}


def test_help_error_code_table_matches_the_handler_sources() -> None:
    defined = _defined_error_codes() - {"invalid_params"} - _TOOL_LEVEL_CODES
    listed = {code for codes in _PARAMETER_ERROR_CODES.values() for code in codes}
    in_band = {code for codes in _LISTED_TOOL_LEVEL_CODES.values() for code in codes}
    assert listed - {"invalid_params"} - in_band == defined


_RAISING_HELPER_CODE_POSITIONS = {
    "ToolError": 0,
    "_validate_text": 3,
    "_require_containing_function": 2,
    "_raise_containment_miss": 2,
    "_run_undo_stack_step": 2,
    "_missing_il_error": 2,
}

# Reached codes no parameter owns (per-window errors, the entry point), so help leaves them out.
_UNLISTED_REACHABLE_CODES = {
    "rex_disasm_many": {"analysis_pending"},
    "rex_quick_main": {"no_function"},
}


def _function_bodies() -> dict[str, list[ast.FunctionDef]]:
    bodies: dict[str, list[ast.FunctionDef]] = {}
    for path in Path(binja_plugin.__file__).parent.rglob("*.py"):
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if isinstance(node, ast.FunctionDef) and _MUTMUT_VARIANT.search(node.name) is None:
                bodies.setdefault(_MUTMUT_ORIGINAL.sub(r"\1", node.name), []).append(node)
    return bodies


def _callee_name(call: ast.Call) -> str:
    target = call.func
    if isinstance(target, ast.Attribute):
        return target.attr
    return target.id if isinstance(target, ast.Name) else ""


def _literal_code(call: ast.Call) -> str | None:
    position = _RAISING_HELPER_CODE_POSITIONS.get(_callee_name(call))
    if position is None or len(call.args) <= position:
        return None
    argument = call.args[position]
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        return argument.value
    return None


def _reachable_error_codes(tool_name: str, skipped: frozenset[str] = frozenset()) -> set[str]:
    bodies = _function_bodies()
    codes: set[str] = set()
    pending, visited = [tool_name], set[str]()
    while pending:
        name = pending.pop()
        if name in visited or name in skipped:
            continue
        visited.add(name)
        calls = [
            node
            for body in bodies.get(name, [])
            for node in ast.walk(body)
            if isinstance(node, ast.Call)
        ]
        pending.extend(_callee_name(call) for call in calls)
        codes.update(code for call in calls if (code := _literal_code(call)) is not None)
    return codes


@pytest.mark.parametrize("tool_name", sorted(tool.name for tool in FakeTool.list()))
def test_help_error_code_table_matches_each_tools_reachable_codes(tool_name: str) -> None:
    reachable = _reachable_error_codes(tool_name)
    unlisted = _UNLISTED_REACHABLE_CODES.get(tool_name, set())
    assert unlisted <= reachable
    listed = {
        code
        for (listed_tool, _), codes in _PARAMETER_ERROR_CODES.items()
        if listed_tool == tool_name
        for code in codes
    }
    in_band = _LISTED_TOOL_LEVEL_CODES.get(tool_name, set())
    assert (
        listed - {"invalid_params"} - in_band
        == reachable - {"invalid_params"} - _TOOL_LEVEL_CODES - unlisted
    )


# Tools whose handlers raise invalid_params for an argument while no parameter lists it:
# known help gaps. The set may only shrink; a tool that lists the code must leave it.
_INVALID_PARAMS_UNLISTED_TOOLS = frozenset(
    {
        "rex_annotate_many",
        "rex_component_add_functions",
        "rex_component_create",
        "rex_component_get",
        "rex_decompile_many",
        "rex_disasm_at",
        "rex_disasm_many",
        "rex_function_constraints",
        "rex_function_define_many",
        "rex_help",
        "rex_hlil_statements",
        "rex_mlil_uses",
        "rex_parameter_variables",
        "rex_report_show",
        "rex_struct_from_access",
        "rex_type_library_import",
        "rex_uidf_clear",
        "rex_uidf_list",
        "rex_uidf_set",
    }
)

_INVALID_PARAMS_GAPS_AT_INTRODUCTION = frozenset(
    {
        "rex_annotate_many",
        "rex_component_add_functions",
        "rex_component_create",
        "rex_component_get",
        "rex_decompile_many",
        "rex_disasm_at",
        "rex_disasm_many",
        "rex_function_constraints",
        "rex_function_define_many",
        "rex_help",
        "rex_hlil_statements",
        "rex_mlil_uses",
        "rex_parameter_variables",
        "rex_report_show",
        "rex_struct_from_access",
        "rex_type_library_import",
        "rex_uidf_clear",
        "rex_uidf_list",
        "rex_uidf_set",
    }
)


def test_the_invalid_params_gap_list_never_gains_a_tool() -> None:
    assert _INVALID_PARAMS_UNLISTED_TOOLS <= _INVALID_PARAMS_GAPS_AT_INTRODUCTION


# Integer range violations are documented by the schema minimum and maximum, not error_codes.
_RANGE_CHECK_HELPERS = frozenset({"_validate_range"})


@pytest.mark.parametrize("tool_name", sorted(tool.name for tool in FakeTool.list()))
def test_a_tool_raising_invalid_params_lists_it_unless_it_is_a_known_gap(tool_name: str) -> None:
    raises = "invalid_params" in _reachable_error_codes(tool_name, _RANGE_CHECK_HELPERS)
    lists = any(
        "invalid_params" in codes
        for (listed_tool, _), codes in _PARAMETER_ERROR_CODES.items()
        if listed_tool == tool_name
    )
    known_gap = tool_name in _INVALID_PARAMS_UNLISTED_TOOLS
    assert (raises and not lists) == known_gap


@pytest.mark.parametrize(
    ("tool_name", "parameter_name", "error_codes"),
    [
        ("rex_constant_find", "function_filter", ["invalid_regex"]),
        ("rex_hlil_grep", "function_filter", ["invalid_regex"]),
        ("rex_hlil_grep", "regex", ["invalid_regex"]),
        ("rex_string_refs", "pattern", ["invalid_regex"]),
        ("rex_function_containing", "addr", ["no_function", "analysis_pending"]),
        ("rex_component_add_functions", "functions", ["analysis_pending"]),
        ("rex_uidf_list", "function", ["analysis_pending"]),
        ("rex_uidf_set_many", "function", ["analysis_pending", "invalid_params"]),
        ("rex_function_define_many", "addresses", []),
    ],
)
def test_help_details_the_error_codes_of_the_parameter_that_raises_them(
    tool_name: str, parameter_name: str, error_codes: list[str]
) -> None:
    parameters = {parameter["name"]: parameter for parameter in _help(tool_name)["parameters"]}
    assert parameters[parameter_name]["error_codes"] == error_codes


def test_help_details_the_dataflow_tool_error_codes() -> None:
    constraints = {
        parameter["name"]: parameter
        for parameter in _help("rex_function_constraints")["parameters"]
    }
    assert constraints["function"]["error_codes"] == ["no_mlil", "analysis_pending"]
    statements = {
        parameter["name"]: parameter for parameter in _help("rex_hlil_statements")["parameters"]
    }
    assert statements["function"]["error_codes"] == ["no_hlil", "analysis_pending"]
    uses = {parameter["name"]: parameter for parameter in _help("rex_mlil_uses")["parameters"]}
    assert uses["function"]["error_codes"] == ["no_mlil", "analysis_pending"]
    assert uses["address"]["error_codes"] == ["no_definition"]
    assert uses["variable"]["error_codes"] == ["no_variable"]
    parameter = {
        parameter["name"]: parameter for parameter in _help("rex_parameter_variables")["parameters"]
    }
    assert parameter["function"]["error_codes"] == ["no_mlil", "analysis_pending"]
    assert parameter["parameter"]["error_codes"] == ["no_variable"]


_EXPORT_FILENAME_CODES = [
    ("", "invalid_params"),
    ("/abs/path.txt", "invalid_params"),
    ("up/../down.txt", "invalid_params"),
    ("back\\slash.txt", "invalid_params"),
    ("nul\x00byte.txt", "invalid_params"),
    ("x" * 256, "invalid_params"),
    (".", "invalid_params"),
    ("sub/", "invalid_params"),
    ("link.txt", "path_escape"),
    ("occupied.txt", "export_failed"),
]

_EXPORT_FILENAME_TOOLS = ["rex_export_disasm", "rex_export_symbols", "rex_type_library_export"]


def _use_export_root_with_traps(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    root.mkdir(parents=True)
    (root / "link.txt").symlink_to(tmp_path / "outside.txt")
    (root / "occupied.txt").mkdir()


def _export_filename_error(tool_name: str, filename: str) -> FakeToolError:
    _, tool = get_tool(tool_name)
    arguments: dict[str, Any] = {"filename": filename}
    if tool_name == "rex_export_disasm":
        view, arguments["address"] = _disasm_view(), 0x1104
    elif tool_name == "rex_export_symbols":
        view, arguments["start"], arguments["end"] = FakeBinaryView(), 0x1000, 0x2000
    else:
        view = FakeBinaryView(arch=FakeArchitecture("x86_64"), types={"open": FakeType("open")})
        arguments["library_name"], arguments["names"] = "recovered", ["open"]
    with pytest.raises(FakeToolError) as error:
        tool(_call(view), **arguments)
    return error.value


@pytest.mark.parametrize("tool_name", _EXPORT_FILENAME_TOOLS)
@pytest.mark.parametrize(("filename", "code"), _EXPORT_FILENAME_CODES)
def test_an_export_filename_raises_the_code_for_its_failure(
    tool_name: str, filename: str, code: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root_with_traps(monkeypatch, tmp_path)
    assert _export_filename_error(tool_name, filename).code == code


@pytest.mark.parametrize("tool_name", _EXPORT_FILENAME_TOOLS)
def test_help_lists_exactly_the_codes_an_export_filename_can_raise(tool_name: str) -> None:
    parameters = {parameter["name"]: parameter for parameter in _help(tool_name)["parameters"]}
    assert parameters["filename"]["error_codes"] == [
        "invalid_params",
        "path_escape",
        "export_failed",
    ]
    assert set(parameters["filename"]["error_codes"]) == {
        code for _, code in _EXPORT_FILENAME_CODES
    }


_EXPORT_REQUIRED = {
    "rex_export_disasm": ["address", "filename"],
    "rex_export_symbols": ["start", "end", "filename"],
    "rex_type_library_export": ["library_name", "names", "filename"],
}


@pytest.mark.parametrize("tool_name", _EXPORT_FILENAME_TOOLS)
def test_help_describes_an_export_filename_as_required_without_a_default(tool_name: str) -> None:
    parameters = {parameter["name"]: parameter for parameter in _help(tool_name)["parameters"]}
    assert parameters["filename"] == {
        "name": "filename",
        "type": "string",
        "required": True,
        "description": "Plain file name inside the export root; overwritten if it exists.",
        "error_codes": ["invalid_params", "path_escape", "export_failed"],
    }


@pytest.mark.parametrize("tool_name", _EXPORT_FILENAME_TOOLS)
def test_an_export_registers_its_filename_as_required(tool_name: str) -> None:
    schema = next(tool for tool in FakeTool.list() if tool.name == tool_name).input_schema
    assert schema["required"] == _EXPORT_REQUIRED[tool_name]
    assert "default" not in schema["properties"]["filename"]


@pytest.mark.parametrize("tool_name", _EXPORT_FILENAME_TOOLS)
def test_an_export_cannot_be_called_without_a_filename(tool_name: str) -> None:
    _, tool = get_tool(tool_name)
    assert inspect.signature(tool).parameters["filename"].default is inspect.Parameter.empty


_INVALID_PARAMS_LISTINGS = {
    *((tool, "filename") for tool in _EXPORT_FILENAME_TOOLS),
    ("rex_type_library_export", "library_name"),
    ("rex_type_library_export", "names"),
    ("rex_type_library_export", "kind"),
    ("rex_uidf_set_many", "function"),
    ("rex_uidf_set_many", "items"),
}


def test_help_lists_invalid_params_only_where_a_parameter_raises_it() -> None:
    listing_invalid_params = {
        key for key, codes in _PARAMETER_ERROR_CODES.items() if "invalid_params" in codes
    }
    assert listing_invalid_params == _INVALID_PARAMS_LISTINGS


def _type_library_export_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **overrides: Any
) -> FakeToolError:
    _use_export_root(monkeypatch, tmp_path).mkdir(parents=True)
    _, tool = get_tool("rex_type_library_export")
    view = FakeBinaryView(arch=FakeArchitecture("x86_64"), types={"open": FakeType("open")})
    arguments: dict[str, Any] = {
        "library_name": "recovered",
        "names": ["open"],
        "filename": "out.bntl",
        **overrides,
    }
    with pytest.raises(FakeToolError) as error:
        tool(_call(view), **arguments)
    return error.value


@pytest.mark.parametrize(
    ("parameter_name", "bad_value"),
    [
        ("names", "open"),
        ("names", []),
        ("names", ["open"] * 129),
        ("names", [3]),
        ("names", [""]),
        ("names", ["x" * 5000]),
        ("kind", "bogus"),
    ],
)
def test_a_bad_type_library_export_names_or_kind_raises_invalid_params_and_help_lists_it(
    parameter_name: str, bad_value: object, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    error = _type_library_export_error(monkeypatch, tmp_path, **{parameter_name: bad_value})
    assert error.code == "invalid_params"
    parameters = {
        parameter["name"]: parameter for parameter in _help("rex_type_library_export")["parameters"]
    }
    assert parameters[parameter_name]["error_codes"] == ["invalid_params"]


def _uidf_batch_view() -> FakeBinaryView:
    rax_1 = FakeVariable("rax_1")
    var_10 = FakeVariable("var_10")
    main = FakeFunction(
        "main",
        0x1100,
        0x1200,
        hlil=RenderableText("return 0"),
        vars=[rax_1, var_10],
        mlil=FakeMediumLevelIL({rax_1: [0x1104], var_10: [0x1190, 0x1196]}),
    )
    leaf = FakeFunction("leaf", 0x2000, 0x2100, vars=[FakeVariable("x")])
    return FakeBinaryView(functions=[main, leaf])


def _uidf_batch_codes(view: FakeBinaryView, address: int, items: list[object]) -> set[str]:
    _, uidf_set_many = get_tool("rex_uidf_set_many")
    result = uidf_set_many(FakeParsingToolCall(view), address, items)
    return {row["error"]["code"] for row in result["results"] if not row["ok"]}


def test_help_lists_exactly_the_codes_a_uidf_set_many_item_can_raise() -> None:
    view = _uidf_batch_view()
    codes = _uidf_batch_codes(
        view,
        0x1100,
        [
            "not-an-object",
            {"variable": "missing", "value": "1"},
            {"variable": "var_10", "value": "1"},
            {"variable": "var_10", "value": "1", "def_address": 0x9999},
            {"variable": "rax_1", "value": "garbage!!"},
        ],
    )
    codes |= _uidf_batch_codes(view, 0x2000, [{"variable": "x", "value": "1"}])
    view.functions[0].set_user_var_value_error = Exception("core refused")
    codes |= _uidf_batch_codes(view, 0x1100, [{"variable": "rax_1", "value": "1"}])
    _, uidf_set_many = get_tool("rex_uidf_set_many")
    with pytest.raises(FakeToolError) as error:
        uidf_set_many(_call(view), 0x1100, [])
    codes.add(error.value.code)
    parameters = {
        parameter["name"]: parameter for parameter in _help("rex_uidf_set_many")["parameters"]
    }
    assert codes == {
        "invalid_params",
        "no_mlil",
        "no_variable",
        "ambiguous_definition",
        "definition_not_found",
        "set_failed",
    }
    assert parameters["items"]["error_codes"] == [
        "invalid_params",
        "no_mlil",
        "no_variable",
        "ambiguous_definition",
        "definition_not_found",
        "set_failed",
    ]


@pytest.mark.parametrize(
    ("library_name", "code"), [("", "invalid_params"), ("x" * 5000, "library_name_too_large")]
)
def test_a_bad_type_library_name_raises_a_code_help_lists(
    library_name: str, code: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert _type_library_export_error(monkeypatch, tmp_path, library_name=library_name).code == code
    parameters = {
        parameter["name"]: parameter for parameter in _help("rex_type_library_export")["parameters"]
    }
    assert code in parameters["library_name"]["error_codes"]
    assert parameters["library_name"]["error_codes"] == [
        "invalid_params",
        "library_name_too_large",
    ]


def test_help_lists_the_codes_a_uidf_set_many_function_can_raise() -> None:
    _, uidf_set_many = get_tool("rex_uidf_set_many")
    items = [{"variable": "rax_1", "value": "1"}]
    codes = set()
    for view, address in [
        (_uidf_batch_view(), 0x9999),
        (FakeBinaryView(pending_functions=[FakeFunction("sub_4000", 0x4000, 0x4010)]), 0x4000),
    ]:
        with pytest.raises(FakeToolError) as error:
            uidf_set_many(FakeParsingToolCall(view), address, items)
        codes.add(error.value.code)
    assert codes == {"invalid_params", "analysis_pending"}
    parameters = {
        parameter["name"]: parameter for parameter in _help("rex_uidf_set_many")["parameters"]
    }
    assert parameters["function"]["error_codes"] == ["analysis_pending", "invalid_params"]
