from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from helpers import (
    REGISTERED_TOOLS,
    FakeBinaryView,
    FakeTool,
    FakeToolError,
    _call,
    get_tool,
)

import binja_plugin
from binja_plugin.tools.help import _PARAMETER_ERROR_CODES

# Error codes the handlers define for the tool as a whole — batch or view-level failures
# no single parameter owns, plus rex_help's own unknown-name rejection. The
# per-parameter table does not list these.
_TOOL_LEVEL_CODES = frozenset(
    {
        "annotate_failed",
        "close_failed",
        "create_failed",
        "finalize_failed",
        "no_arch",
        "redo_failed",
        "undo_failed",
        "unknown_tool",
    }
)

_MUTMUT_VARIANT = re.compile(r"__mutmut_\d+$")


def _help(tool_name: str = "") -> Any:
    _, function = get_tool("rex_help")
    return function(_call(FakeBinaryView()), tool_name=tool_name)


def test_help_lists_every_rex_tool_with_its_purpose() -> None:
    tools = _help()["tools"]
    assert [tool["name"] for tool in tools] == sorted(name for name, _, _ in REGISTERED_TOOLS)
    search = tools[[tool["name"] for tool in tools].index("rex_string_search")]
    assert search["description"] == (
        "Search the binary's detected strings by substring or regular expression."
    )


def test_help_lists_itself() -> None:
    assert {
        "name": "rex_help",
        "description": "Describe the plugin's rex_ tools from the mcp registry.",
    } in _help()["tools"]


def test_help_excludes_non_rex_registry_entries() -> None:
    def bn_builtin(call: object) -> dict[str, object]:
        """A stand-in for a built-in bn_ tool.

        :param call: The tool call.
        """
        return {}

    saved = list(REGISTERED_TOOLS)
    REGISTERED_TOOLS.append(("bn_builtin", {}, bn_builtin))
    try:
        names = [tool["name"] for tool in _help()["tools"]]
    finally:
        REGISTERED_TOOLS[:] = saved
    assert "bn_builtin" not in names
    assert "rex_string_search" in names


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
        "error_codes": [],
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


def test_help_details_required_flags_and_per_parameter_error_codes() -> None:
    by_name = {parameter["name"]: parameter for parameter in _help("rex_data_find")["parameters"]}
    assert by_name["pattern"]["required"] is True
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


def test_help_details_non_empty_strings_and_itself() -> None:
    by_name = {parameter["name"]: parameter for parameter in _help("rex_report_show")["parameters"]}
    assert by_name["title"]["minLength"] == 1
    assert by_name["title"]["error_codes"] == ["title_too_large"]

    own = {parameter["name"]: parameter for parameter in _help("rex_help")["parameters"]}
    assert own["tool_name"] == {
        "name": "tool_name",
        "type": "string",
        "required": False,
        "description": "rex_ tool to describe; empty lists every rex_ tool's name and purpose.",
        "error_codes": [],
        "default": "",
    }


def test_help_fails_on_an_unknown_name_and_lists_the_valid_ones() -> None:
    with pytest.raises(FakeToolError) as exc:
        _help("rex_nope")
    assert exc.value.code == "unknown_tool"
    assert "no rex_ tool named 'rex_nope'" in exc.value.message
    assert "rex_string_search" in exc.value.message


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
    code_positions = {"ToolError": 0, "_validate_text": 3, "_require_containing_function": 2}
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


def test_help_error_code_table_matches_the_handler_sources() -> None:
    defined = _defined_error_codes() - {"invalid_params"} - _TOOL_LEVEL_CODES
    listed = {code for codes in _PARAMETER_ERROR_CODES.values() for code in codes}
    assert listed == defined
