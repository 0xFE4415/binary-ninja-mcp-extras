from __future__ import annotations

from typing import Any

import pytest
from helpers import FakeTool, FakeToolError, _call, get_tool
from helpers_view import FakeBinaryView, FakeFunction

_MAX_UINT64 = 2**64 - 1


def _find(value: object, references: list[Any] | None = None) -> dict[str, Any]:
    function = FakeFunction("code", 0x1000, 0x1100)
    view = FakeBinaryView(
        functions=[function],
        constant_references=[(0x20, 0x1010, function), (_MAX_UINT64, 0x1020, function)]
        if references is None
        else references,
    )
    _, find = get_tool("rex_constant_find")
    return find(_call(view), value=value)


def _addresses(result: dict[str, Any]) -> list[str]:
    return [address for entry in result["functions"] for address in entry["addresses"]]


@pytest.mark.parametrize(
    ("text", "addresses"),
    [
        ("0x20", ["0x1010"]),
        ("0X20", ["0x1010"]),
        ("0x0020", ["0x1010"]),
        ("0x0000000000000020", ["0x1010"]),
        ("0xffffffffffffffff", ["0x1020"]),
        ("0xFFFFFFFFFFFFFFFF", ["0x1020"]),
        ("0xFfFfFfFfFfFfFfFf", ["0x1020"]),
        ("0x21", []),
    ],
)
def test_constant_find_accepts_a_hex_string_value(text: str, addresses: list[str]) -> None:
    assert _addresses(_find(text)) == addresses


def test_a_hex_string_and_the_integer_find_the_same_constant() -> None:
    assert _find("0xffffffffffffffff") == _find(_MAX_UINT64)
    assert _find("0x20") == _find(0x20)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "must start with 0x"),
        ("20", "must start with 0x"),
        ("ff", "must start with 0x"),
        ("-0x1", "must start with 0x"),
        ("+0x1", "must start with 0x"),
        (" 0x1", "must start with 0x"),
        ("\t0x1", "must start with 0x"),
        ("0b1", "must start with 0x"),
        ("1e3", "must start with 0x"),
        ("x20", "must start with 0x"),
        ("0x", "needs at least one hex digit after 0x"),
        ("0X", "needs at least one hex digit after 0x"),
        ("0x1 ", "may contain only hex digits after 0x"),
        ("0x 1", "may contain only hex digits after 0x"),
        ("0x1\n", "may contain only hex digits after 0x"),
        ("0xg", "may contain only hex digits after 0x"),
        ("0x-1", "may contain only hex digits after 0x"),
        ("0x1_0", "may contain only hex digits after 0x"),
        ("0x0x1", "may contain only hex digits after 0x"),
        ("0x١", "may contain only hex digits after 0x"),
        ("0xＡ", "may contain only hex digits after 0x"),
        ("0x10000000000000000", "may have at most 16 hex digits (64 bits)"),
        ("0x00000000000000001", "may have at most 16 hex digits (64 bits)"),
        ("0x" + "f" * 100000, "may have at most 16 hex digits (64 bits)"),
    ],
)
def test_constant_find_rejects_a_malformed_hex_string(text: str, message: str) -> None:
    with pytest.raises(FakeToolError) as exc:
        _find(text)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == f"Invalid hex parameter 'value': {message}"


def test_integer_values_keep_their_bounds_with_the_union_type() -> None:
    assert _addresses(_find(0x20)) == ["0x1010"]
    assert _addresses(_find(_MAX_UINT64)) == ["0x1020"]
    for value, message in ((-1, "at least 0"), (2**64, f"at most {_MAX_UINT64}")):
        with pytest.raises(FakeToolError) as exc:
            _find(value)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == f"Invalid integer parameter 'value': Must be {message}"


def test_constant_find_advertises_an_integer_or_hex_string_value() -> None:
    options, function = get_tool("rex_constant_find")
    schema = FakeTool("rex_constant_find", options, function).input_schema
    value_schema = schema["properties"]["value"]
    assert value_schema["type"] == ["integer", "string"]
    assert value_schema["minimum"] == 0
    assert value_schema["maximum"] == _MAX_UINT64
    assert value_schema["pattern"] == "^0[xX][0-9a-fA-F]{1,16}$"
    assert "0x" in value_schema["description"]
    assert "value" in schema["required"]


def test_rex_help_renders_the_union_typed_value_parameter() -> None:
    _, help_tool = get_tool("rex_help")
    detail = help_tool(_call(FakeBinaryView()), tool_name="rex_constant_find", category="")
    by_name = {parameter["name"]: parameter for parameter in detail["parameters"]}
    value = by_name["value"]
    assert value["type"] == ["integer", "string"]
    assert value["required"] is True
    assert value["minimum"] == 0
    assert value["maximum"] == _MAX_UINT64
    assert "0x" in value["description"]
    assert value["error_codes"] == ["invalid_params"]
    assert [parameter["name"] for parameter in detail["parameters"]] == [
        "value",
        "function_filter",
        "limit",
        "offset",
        "include_non_operand_hits",
    ]


@pytest.mark.parametrize(
    "value",
    [True, False, 1.5, 2.0, None, [], [1], {}, {"value": 1}, b"0x20"],
    ids=[
        "true",
        "false",
        "float",
        "whole-float",
        "null",
        "list",
        "list-1",
        "dict",
        "dict-1",
        "bytes",
    ],
)
def test_constant_find_rejects_a_value_that_is_neither_an_integer_nor_a_string(
    value: object,
) -> None:
    with pytest.raises(FakeToolError) as exc:
        _find(value)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Expected integer or hex string parameter 'value'"


def test_a_rejected_boolean_does_not_search_for_zero_or_one() -> None:
    function = FakeFunction("code", 0x1000, 0x1100)
    view = FakeBinaryView(
        functions=[function], constant_references=[(0, 0x1010, function), (1, 0x1020, function)]
    )
    _, find = get_tool("rex_constant_find")
    for value in (True, False):
        with pytest.raises(FakeToolError):
            find(_call(view), value=value)
    assert view.constant_scan_yields == 0
