from __future__ import annotations

import inspect
import sys
from pathlib import Path
from typing import Any

import pytest
from binaryninja import mcp
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

from binja_plugin.tools.help import (
    _CATEGORY_USE_WHEN,
    _UNCATEGORIZED,
    _UNCATEGORIZED_USE_WHEN,
)
from binja_plugin.tools.scanning import _MAX_PATTERN_CHARS


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
            "bn_binary_triage gives the entry point; read its HLIL or disassembly, grep HLIL."
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
        "description": ("Describe the rex_ tools, and rx_ tools if present, from the registry."),
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
        "default": "",
    }
    assert by_name["limit"] == {
        "name": "limit",
        "type": "integer",
        "required": False,
        "description": "Maximum strings to return.",
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
        'Bounded call paths. "Does A reach B?" is from_addr=A, to_addr=B, direction="callees".'
    )
    by_name = {parameter["name"]: parameter for parameter in detail["parameters"]}
    assert by_name["direction"]["default"] == "callers"
    assert by_name["direction"]["description"] == (
        '"callees": from_addr reaches to_addr; "callers" (default): the reverse.'
    )


def test_help_details_required_flags_and_bounds() -> None:
    by_name = {parameter["name"]: parameter for parameter in _help("rex_data_find")["parameters"]}
    assert by_name["pattern"]["required"] is True
    assert by_name["pattern"]["maxLength"] == _MAX_PATTERN_CHARS
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

    own = {parameter["name"]: parameter for parameter in _help("rex_help")["parameters"]}
    assert own["tool_name"] == {
        "name": "tool_name",
        "type": "string",
        "required": False,
        "description": "Tool whose parameters to describe; empty selects the category views.",
        "default": "",
    }
    assert own["category"] == {
        "name": "category",
        "type": "string",
        "required": False,
        "description": "Category whose tools to list with purposes; empty lists the categories.",
        "default": "",
    }


def test_help_fails_on_an_unknown_name_and_lists_the_valid_ones() -> None:
    with pytest.raises(FakeToolError) as exc:
        _help("rex_nope")
    assert exc.value.code == "unknown_tool"
    registered = ", ".join(sorted(tool.name for tool in FakeTool.list()))
    expected = f"no tool named 'rex_nope'; registered tools: {registered}"
    assert exc.value.message == expected


def test_help_uncategorized_category_reports_the_uncategorized_use_when() -> None:
    listing = _help(category="other")
    assert listing["use_when"] == _UNCATEGORIZED_USE_WHEN


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
    ("linkdir", "path_escape"),
    ("linkdir/out.txt", "path_escape"),
    ("inner_link", "invalid_params"),
    ("occupied.txt", "invalid_params"),
    ("missing/out.txt", "invalid_params"),
    ("regular.txt/out.txt", "invalid_params"),
    ("regular.txt/deeper/out.txt", "invalid_params"),
]

_EXPORT_FILENAME_TOOLS = ["rex_export_disasm", "rex_export_symbols", "rex_type_library_export"]


def _use_export_root_with_traps(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    root.mkdir(parents=True)
    (root / "link.txt").symlink_to(tmp_path / "outside.txt")
    (tmp_path / "outside_dir").mkdir()
    (root / "linkdir").symlink_to(tmp_path / "outside_dir")
    (root / "occupied.txt").mkdir()
    (root / "inner_dir").mkdir()
    (root / "inner_link").symlink_to(root / "inner_dir")
    (root / "regular.txt").write_text("a file, not a directory")


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
def test_a_bad_type_library_export_names_or_kind_raises_invalid_params(
    parameter_name: str, bad_value: object, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    error = _type_library_export_error(monkeypatch, tmp_path, **{parameter_name: bad_value})
    assert error.code == "invalid_params"


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


def test_a_uidf_set_many_item_reports_each_failure_code() -> None:
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
    assert codes == {
        "invalid_params",
        "no_mlil",
        "no_variable",
        "ambiguous_definition",
        "definition_not_found",
        "set_failed",
    }


@pytest.mark.parametrize(
    ("library_name", "code"), [("", "invalid_params"), ("x" * 5000, "library_name_too_large")]
)
def test_a_bad_type_library_name_raises_its_code(
    library_name: str, code: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert _type_library_export_error(monkeypatch, tmp_path, library_name=library_name).code == code


def test_a_uidf_set_many_function_raises_its_code() -> None:
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


def test_help_registers_with_global_scope_so_it_needs_no_binary() -> None:
    options, _ = get_tool("rex_help")
    assert options["scope"] == mcp.McpToolScope.GlobalScope
