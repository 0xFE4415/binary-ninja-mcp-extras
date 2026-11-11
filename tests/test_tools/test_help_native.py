from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from helpers import FakeTool, FakeToolError, _call, get_tool
from helpers_view import FakeBinaryView

from binja_plugin.tools.help import _PARAMETER_ERROR_CODES

_MAX_PATTERN_CHARS = 8192

_PATTERN_DESCRIPTION = (
    'Hex byte pattern, e.g. "48 8b ?? 05"; each byte is 2 ASCII hex digits or "??".'
)


class FakeNativeTool:
    """A tool the native plugin registers: a name, a description, and a schemars-style schema."""

    def __init__(self, name: str, description: str, input_schema: dict[str, Any]) -> None:
        self.name = name
        self.description = description
        self.input_schema = input_schema


_LIMIT_SCHEMA = {
    "description": "Maximum matches to return.",
    "type": "integer",
    "format": "uint32",
    "default": 50,
    "minimum": 0,
    "maximum": 500,
}
_OFFSET_SCHEMA = {
    "description": "Matches to skip before collecting results.",
    "type": "integer",
    "format": "uint64",
    "default": 0,
    "minimum": 0,
}
_SECTION_SCHEMA = {
    "description": "Only search within this section.",
    "type": ["string", "null"],
    "default": None,
}

RX_DATA_FIND = FakeNativeTool(
    "rx_data_find",
    "Search mapped memory for a hex pattern in Rust.",
    {
        "type": "object",
        "properties": {
            "limit": _LIMIT_SCHEMA,
            "offset": _OFFSET_SCHEMA,
            "pattern": {
                "description": _PATTERN_DESCRIPTION,
                "type": "string",
                "maxLength": _MAX_PATTERN_CHARS,
            },
            "section": _SECTION_SCHEMA,
        },
        "required": ["pattern"],
        "additionalProperties": False,
    },
)

RX_MULTI_FIND = FakeNativeTool(
    "rx_multi_find",
    "Search up to 64 hex patterns in one Rust pass.",
    {
        "type": "object",
        "properties": {
            "limit": _LIMIT_SCHEMA,
            "offset": _OFFSET_SCHEMA,
            "patterns": {
                "description": 'Hex byte patterns, e.g. ["48 8b ?? 05"].',
                "type": "array",
                "items": {"type": "string", "maxLength": _MAX_PATTERN_CHARS},
                "minItems": 1,
                "maxItems": 64,
            },
            "section": _SECTION_SCHEMA,
        },
        "required": ["patterns"],
        "additionalProperties": False,
    },
)


def _help(tool_name: str = "", category: str = "") -> Any:
    _, function = get_tool("rex_help")
    return function(_call(FakeBinaryView()), tool_name=tool_name, category=category)


def _register_native(monkeypatch: pytest.MonkeyPatch, *tools: FakeNativeTool) -> None:
    python_tools = FakeTool.list()
    monkeypatch.setattr(FakeTool, "list", staticmethod(lambda: [*python_tools, *tools]))


def _parameters(tool_name: str) -> dict[str, Any]:
    return {parameter["name"]: parameter for parameter in _help(tool_name)["parameters"]}


def _scanning_names() -> list[str]:
    entries = {entry["name"]: entry for entry in _help()["categories"]}
    return list(entries["scanning"]["tools"])


def test_the_native_tools_are_not_listed_while_they_are_not_registered() -> None:
    names = [name for entry in _help()["categories"] for name in entry["tools"]]
    assert not [name for name in names if name.startswith("rx_")]
    assert not [
        tool["name"] for tool in _help(category="scanning")["tools"] if "rx_" in tool["name"]
    ]


@pytest.mark.parametrize("tool_name", ["rx_data_find", "rx_multi_find"])
def test_an_unregistered_native_tool_is_an_unknown_tool(tool_name: str) -> None:
    with pytest.raises(FakeToolError) as error:
        _help(tool_name)
    assert error.value.code == "unknown_tool"
    prefix = f"no tool named '{tool_name}'; registered tools: "
    assert error.value.message.startswith(prefix)
    registered = error.value.message.removeprefix(prefix).split(", ")
    assert registered == sorted(tool.name for tool in FakeTool.list())
    assert not [name for name in registered if name.startswith("rx_")]


def test_registered_native_tools_join_the_scanning_category(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _scanning_names()
    _register_native(monkeypatch, RX_MULTI_FIND, RX_DATA_FIND)
    assert _scanning_names() == sorted([*before, "rx_data_find", "rx_multi_find"])
    index = {entry["name"]: entry["tools"] for entry in _help()["categories"]}
    assert "other" not in index
    listed = [name for names in index.values() for name in names]
    assert sorted(listed) == sorted(tool.name for tool in FakeTool.list())


def test_the_scanning_category_view_describes_the_native_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _register_native(monkeypatch, RX_DATA_FIND, RX_MULTI_FIND)
    view = _help(category="scanning")
    described = {tool["name"]: tool["description"] for tool in view["tools"]}
    assert described["rx_data_find"] == RX_DATA_FIND.description
    assert described["rx_multi_find"] == RX_MULTI_FIND.description
    assert "rex_data_find" in described


@pytest.mark.parametrize("name", ["rx_foo", "rx_data_find2", "rxdata", "bn_rx_find"])
def test_only_our_native_tools_are_listed_by_exact_name(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    _register_native(
        monkeypatch, FakeNativeTool(name, "Another plugin's tool.", {"type": "object"})
    )
    names = [tool for entry in _help()["categories"] for tool in entry["tools"]]
    assert name not in names
    assert "other" not in [entry["name"] for entry in _help()["categories"]]
    assert name not in [tool["name"] for tool in _help(category="scanning")["tools"]]
    with pytest.raises(FakeToolError) as error:
        _help(name)
    assert error.value.code == "unknown_tool"


def test_help_describes_rx_data_find_parameters_with_list_typed_and_bounded_schemas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _register_native(monkeypatch, RX_DATA_FIND)
    detail = _help("rx_data_find")
    assert detail["name"] == "rx_data_find"
    assert detail["description"] == RX_DATA_FIND.description
    assert list(_parameters("rx_data_find")) == ["limit", "offset", "pattern", "section"]
    parameters = _parameters("rx_data_find")
    assert parameters["pattern"] == {
        "name": "pattern",
        "type": "string",
        "required": True,
        "description": _PATTERN_DESCRIPTION,
        "error_codes": ["invalid_params", "pattern_too_large", "invalid_pattern"],
        "maxLength": _MAX_PATTERN_CHARS,
    }
    assert parameters["section"] == {
        "name": "section",
        "type": ["string", "null"],
        "required": False,
        "description": "Only search within this section.",
        "error_codes": ["section_not_found"],
        "default": None,
    }
    assert parameters["limit"]["default"] == 50
    assert parameters["limit"]["minimum"] == 0
    assert parameters["limit"]["maximum"] == 500
    assert parameters["limit"]["error_codes"] == []
    assert parameters["offset"]["required"] is False


def test_help_describes_rx_multi_find_pattern_list_and_its_caps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _register_native(monkeypatch, RX_MULTI_FIND)
    patterns = _parameters("rx_multi_find")["patterns"]
    assert patterns["type"] == "array"
    assert patterns["required"] is True
    assert patterns["items"] == {"type": "string", "maxLength": _MAX_PATTERN_CHARS}
    assert patterns["minItems"] == 1
    assert patterns["maxItems"] == 64
    assert patterns["error_codes"] == [
        "invalid_params",
        "too_many_patterns",
        "pattern_too_large",
        "invalid_pattern",
    ]
    assert _parameters("rx_multi_find")["section"]["error_codes"] == ["section_not_found"]


def test_help_tolerates_a_native_parameter_without_description_or_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bare = FakeNativeTool(
        "rx_multi_find",
        "A tool with sparse schemas.",
        {
            "type": "object",
            "properties": {
                "mode": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                "count": {"type": "integer"},
            },
        },
    )
    _register_native(monkeypatch, bare)
    parameters = _parameters("rx_multi_find")
    assert parameters["mode"] == {
        "name": "mode",
        "type": None,
        "required": False,
        "description": "",
        "error_codes": [],
    }
    assert parameters["count"]["description"] == ""
    assert parameters["count"]["type"] == "integer"


def test_help_tolerates_a_native_tool_without_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    _register_native(
        monkeypatch, FakeNativeTool("rx_multi_find", "Takes nothing.", {"type": "object"})
    )
    detail = _help("rx_multi_find")
    assert detail == {"name": "rx_multi_find", "description": "Takes nothing.", "parameters": []}


def test_every_native_error_code_entry_names_a_parameter_of_a_native_tool() -> None:
    native_keys = {key for key in _PARAMETER_ERROR_CODES if key[0].startswith("rx_")}
    schema_keys = {
        (tool.name, parameter_name)
        for tool in (RX_DATA_FIND, RX_MULTI_FIND)
        for parameter_name in tool.input_schema["properties"]
    }
    assert native_keys <= schema_keys


_NATIVE_TOOLS_SOURCE = Path(__file__).resolve().parents[2] / "native" / "src" / "tools"
_LINE_COMMENT = re.compile(r"//[^\n]*")
_TEST_MODULE = re.compile(r"#\[cfg\(test\)\]\s*mod tests\b")
_LITERAL_ERROR_CODE = re.compile(r'McpToolError::new\(\s*"([a-z_]+)"')


# Sees only literal codes in McpToolError::new/invalid_params calls above `mod tests`; a code
# passed through a variable is invisible. Skipped where native/ is not copied (mutants).
def test_the_native_error_codes_listed_are_the_literal_ones_the_rust_source_raises() -> None:
    if not _NATIVE_TOOLS_SOURCE.is_dir():
        pytest.skip("the native sources are not part of this tree")
    sources = sorted(_NATIVE_TOOLS_SOURCE.rglob("*.rs"))
    assert {path.name for path in sources} >= {"mod.rs", "data_find.rs", "multi_find.rs"}
    raised: set[str] = set()
    for path in sources:
        text = _TEST_MODULE.split(path.read_text(encoding="utf-8"))[0]
        code = _LINE_COMMENT.sub("", text)
        raised.update(_LITERAL_ERROR_CODE.findall(code))
        if "McpToolError::invalid_params(" in code:
            raised.add("invalid_params")
    listed = {
        code
        for (tool_name, _), codes in _PARAMETER_ERROR_CODES.items()
        if tool_name.startswith("rx_")
        for code in codes
    }
    assert raised == listed
