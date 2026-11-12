from __future__ import annotations

import json
from typing import Any

import pytest
from helpers import REGISTERED_TOOLS, FakeTool, _call, get_tool
from helpers_view import FakeBinaryView, FakeFunction

_MAX_UINT64 = 18446744073709551615
_BOUND_KEYWORDS = ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "maxLength")


def _bounds(schema: object, path: str = "") -> list[tuple[str, object]]:
    found: list[tuple[str, object]] = []
    if isinstance(schema, dict):
        for key, child in schema.items():
            if key in _BOUND_KEYWORDS:
                found.append((f"{path}/{key}", child))
            found.extend(_bounds(child, f"{path}/{key}"))
    elif isinstance(schema, list):
        for index, child in enumerate(schema):
            found.extend(_bounds(child, f"{path}[{index}]"))
    return found


def test_constant_find_advertises_the_exact_uint64_maximum() -> None:
    options, function = get_tool("rex_constant_find")
    value_schema = FakeTool("rex_constant_find", options, function).input_schema["properties"][
        "value"
    ]
    assert value_schema["maximum"] == _MAX_UINT64
    assert type(value_schema["maximum"]) is int
    assert "18446744073709552000" not in json.dumps(value_schema)
    assert json.dumps(value_schema["maximum"]) == "18446744073709551615"


def test_every_numeric_schema_bound_is_an_exact_integer() -> None:
    bounds: list[tuple[str, object]] = []
    for name, options, function in REGISTERED_TOOLS:
        schema = FakeTool(name, options, function).input_schema
        bounds.extend((f"{name}{path}", bound) for path, bound in _bounds(schema))
    assert bounds
    exact_bounds: dict[str, int] = {}
    for path, bound in bounds:
        assert isinstance(bound, int) and type(bound) is int, f"{path} is {bound!r}, not an int"
        if bound > 2**53:
            exact_bounds[path] = bound
    assert exact_bounds == {"rex_constant_find/properties/value/maximum": _MAX_UINT64}


def test_rex_help_reports_the_exact_constant_find_maximum() -> None:
    _, help_tool = get_tool("rex_help")
    detail = help_tool(_call(FakeBinaryView()), tool_name="rex_constant_find", category="")
    by_name: dict[str, Any] = {parameter["name"]: parameter for parameter in detail["parameters"]}
    assert by_name["value"]["maximum"] == _MAX_UINT64
    assert type(by_name["value"]["maximum"]) is int


@pytest.mark.parametrize("value", [_MAX_UINT64, _MAX_UINT64 - 1])
def test_constant_find_accepts_values_up_to_the_uint64_maximum(value: int) -> None:
    function = FakeFunction("code", 0x1000, 0x1100)
    view = FakeBinaryView(functions=[function], constant_references=[(value, 0x1010, function)])
    _, find = get_tool("rex_constant_find")
    assert find(_call(view), value=value) == {
        "total": 1,
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "code",
                "addresses": ["0x1010"],
                "addresses_truncated": False,
            }
        ],
    }
