from __future__ import annotations

from typing import override

import pytest
from helpers import FakeTool, FakeToolError, _call, get_tool
from helpers_invoke import invoke_tool
from helpers_view import FakeBinaryView, FakeSegment, FakeStringReference

REPLACEMENT = "�"


class CoreTruncatingView(FakeBinaryView):
    """A section lookup that reads the name as a C string, like the core binding."""

    @override
    def get_section_by_name(self, name: str) -> object:
        return super().get_section_by_name(name.split("\x00")[0])


def _view() -> CoreTruncatingView:
    return CoreTruncatingView(
        segments=[FakeSegment(0x1000, 4)],
        memory={0x1000: b"\x90\x90\x90\x90"},
        sections={".text": (0x1000, 0x1004)},
        strings=[FakeStringReference("hello", 0x1000)],
    )


def _error(tool_name: str, **arguments: object) -> FakeToolError:
    _, tool = get_tool(tool_name)
    with pytest.raises(FakeToolError) as caught:
        invoke_tool(tool, _call(_view()), **arguments)
    return caught.value


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [("rex_data_find", {"pattern": "90"}), ("rex_string_search", {})],
)
def test_a_section_name_with_nul_is_not_found_instead_of_scanning_its_prefix(
    tool_name: str, arguments: dict[str, object]
) -> None:
    error = _error(tool_name, section=".text\x00z", **arguments)
    assert error.code == "section_not_found"
    assert error.message == f"no section named '.text{REPLACEMENT}z'"


def test_a_section_name_with_nul_is_reported_like_an_unknown_name() -> None:
    nul_error = _error("rex_data_find", pattern="90", section="x\x00")
    plain_error = _error("rex_data_find", pattern="90", section="xy")
    assert nul_error.code == plain_error.code
    assert nul_error.message == f"no section named 'x{REPLACEMENT}'"
    assert plain_error.message == "no section named 'xy'"


def test_a_long_section_name_with_nul_is_truncated_after_the_replacement() -> None:
    error = _error("rex_data_find", pattern="90", section="\x00" + "a" * 600)
    assert error.message == (f"no section named '{REPLACEMENT}{'a' * 511}... [89 chars truncated]'")


@pytest.mark.parametrize("tool_name", ["rex_data_find", "rex_find_functions_by_pattern"])
def test_an_invalid_pattern_error_renders_nul_as_the_replacement_character(
    tool_name: str,
) -> None:
    error = _error(tool_name, pattern="\x00z")
    assert error.code == "invalid_pattern"
    assert error.message == f"invalid hex byte token '{REPLACEMENT}z'"


@pytest.mark.parametrize("tool_name", ["rex_data_find", "rex_find_functions_by_pattern"])
@pytest.mark.parametrize("pattern", [5, True, False, None, 1.5, ["90"], {"a": 1}, b"90"])
def test_a_non_string_pattern_is_invalid_params(tool_name: str, pattern: object) -> None:
    error = _error(tool_name, pattern=pattern)
    assert error.code == "invalid_params"
    assert error.message == "Expected string parameter 'pattern'"


def test_a_non_string_pattern_is_rejected_before_the_section_lookup() -> None:
    error = _error("rex_data_find", pattern=5, section="nope")
    assert error.code == "invalid_params"


@pytest.mark.parametrize("tool_name", ["rex_data_find", "rex_find_functions_by_pattern"])
def test_the_pattern_schema_is_a_required_plain_string(tool_name: str) -> None:
    options, function = get_tool(tool_name)
    schema = FakeTool(tool_name, options, function).input_schema
    assert schema["properties"]["pattern"]["type"] == "string"
    assert "maxLength" not in schema["properties"]["pattern"]
    assert schema["properties"]["pattern"]["description"]
    assert "pattern" in schema["required"]
