from __future__ import annotations

from typing import Any

import pytest
from helpers import FakeTool, _call, get_tool
from helpers_view import (
    ANNOTATED_INSTRUCTION_LINE,
    INSTRUCTION_LINE,
    NO_OPERAND,
    PUSH_ZERO_LINE,
    SHIFT_BY_ONE_LINE,
    STRING_ANNOTATION_LINE,
    XOR_REGISTER_LINE,
    FakeBinaryView,
    FakeConstantReference,
    FakeFunction,
    FakeInstructionTextTokenType,
    FakeLineToken,
)

_TOKEN_TYPE = FakeInstructionTextTokenType
_EMPTY = {"total": 0, "truncated": False, "functions": []}


def _entry(start: int, name: str, addresses: list[int], truncated: bool = False) -> dict[str, Any]:
    return {
        "start": hex(start),
        "name": name,
        "addresses": [hex(address) for address in addresses],
        "addresses_truncated": truncated,
    }


def _find(
    functions: list[FakeFunction], references: list[FakeConstantReference], **options: Any
) -> dict[str, Any]:
    _, find = get_tool("rex_constant_find")
    view = FakeBinaryView(functions=functions, constant_references=references)
    return find(_call(view), **options)


def _zero_hit(function: FakeFunction, address: int, line: tuple[FakeLineToken, ...]) -> Any:
    return (0, address, function, line)


@pytest.mark.parametrize(
    "line",
    [XOR_REGISTER_LINE, SHIFT_BY_ONE_LINE, STRING_ANNOTATION_LINE, ANNOTATED_INSTRUCTION_LINE],
    ids=["xor-register", "shift-by-one", "string-annotation", "annotated-register"],
)
def test_zero_hits_without_a_zero_immediate_are_dropped_by_default(
    line: tuple[FakeLineToken, ...],
) -> None:
    function = FakeFunction("code", 0x1000, 0x1100)
    assert _find([function], [_zero_hit(function, 0x1010, line)], value=0) == _EMPTY


@pytest.mark.parametrize(
    "line",
    [XOR_REGISTER_LINE, SHIFT_BY_ONE_LINE, STRING_ANNOTATION_LINE, ANNOTATED_INSTRUCTION_LINE],
    ids=["xor-register", "shift-by-one", "string-annotation", "annotated-register"],
)
def test_include_implicit_zero_restores_the_dropped_hits(
    line: tuple[FakeLineToken, ...],
) -> None:
    function = FakeFunction("code", 0x1000, 0x1100)
    result = _find(
        [function], [_zero_hit(function, 0x1010, line)], value=0, include_implicit_zero=True
    )
    assert result == {
        "total": 1,
        "truncated": False,
        "functions": [_entry(0x1000, "code", [0x1010])],
    }


@pytest.mark.parametrize(
    "line", [INSTRUCTION_LINE, PUSH_ZERO_LINE], ids=["integer-operand", "possible-address-operand"]
)
def test_zero_immediate_operands_are_kept_with_or_without_the_option(
    line: tuple[FakeLineToken, ...],
) -> None:
    function = FakeFunction("code", 0x1000, 0x1100)
    references = [_zero_hit(function, 0x1010, line)]
    expected = {"total": 1, "truncated": False, "functions": [_entry(0x1000, "code", [0x1010])]}
    assert _find([function], references, value=0) == expected
    assert _find([function], references, value=0, include_implicit_zero=True) == expected


def test_a_register_token_alone_never_counts_as_a_zero_immediate() -> None:
    function = FakeFunction("code", 0x1000, 0x1100)
    registers_only = (
        FakeLineToken(_TOKEN_TYPE.InstructionToken, "mov"),
        FakeLineToken(_TOKEN_TYPE.RegisterToken, "rax", 0, 0),
        FakeLineToken(_TOKEN_TYPE.RegisterToken, "rbx", 0, 1),
    )
    assert _find([function], [_zero_hit(function, 0x1010, registers_only)], value=0) == _EMPTY


def test_a_zero_integer_outside_any_operand_never_counts_as_a_zero_immediate() -> None:
    function = FakeFunction("code", 0x1000, 0x1100)
    for token_type in (_TOKEN_TYPE.IntegerToken, _TOKEN_TYPE.PossibleAddressToken):
        line = (
            FakeLineToken(_TOKEN_TYPE.InstructionToken, "xor"),
            FakeLineToken(token_type, "0x0", 0, NO_OPERAND),
        )
        assert _find([function], [_zero_hit(function, 0x1010, line)], value=0) == _EMPTY


def test_a_nonzero_integer_operand_never_counts_as_a_zero_immediate() -> None:
    function = FakeFunction("code", 0x1000, 0x1100)
    for token_type in (_TOKEN_TYPE.IntegerToken, _TOKEN_TYPE.PossibleAddressToken):
        line = (
            FakeLineToken(_TOKEN_TYPE.InstructionToken, "add"),
            FakeLineToken(token_type, "0x1", 1, 1),
        )
        assert _find([function], [_zero_hit(function, 0x1010, line)], value=0) == _EMPTY


def test_a_zero_immediate_anywhere_on_the_line_keeps_the_hit() -> None:
    function = FakeFunction("code", 0x1000, 0x1100)
    line = (
        FakeLineToken(_TOKEN_TYPE.InstructionToken, "mov"),
        FakeLineToken(_TOKEN_TYPE.IntegerToken, "0xf0", 0xF0, 0),
        FakeLineToken(_TOKEN_TYPE.AnnotationToken, "  {"),
        FakeLineToken(_TOKEN_TYPE.IntegerToken, "0x5", 5),
        FakeLineToken(_TOKEN_TYPE.PossibleAddressToken, "0x0", 0, 1),
    )
    result = _find([function], [_zero_hit(function, 0x1010, line)], value=0)
    assert result["functions"] == [_entry(0x1000, "code", [0x1010])]


def test_the_filter_applies_to_value_zero_only() -> None:
    function = FakeFunction("code", 0x1000, 0x1100)
    result = _find([function], [(3, 0x1010, function, ANNOTATED_INSTRUCTION_LINE)], value=3)
    assert result["functions"] == [_entry(0x1000, "code", [0x1010])]
    symbol_address = (
        FakeLineToken(_TOKEN_TYPE.InstructionToken, "lea"),
        FakeLineToken(_TOKEN_TYPE.CodeSymbolToken, "data_404501", 0x404501, 1),
    )
    result = _find([function], [(0x404501, 0x1020, function, symbol_address)], value=0x404501)
    assert result["functions"] == [_entry(0x1000, "code", [0x1020])]


def test_dropped_hits_neither_create_a_function_nor_use_the_address_cap() -> None:
    xor_only = FakeFunction("xor_only", 0x1000, 0x1100)
    mixed = FakeFunction("mixed", 0x2000, 0x2100)
    references = [_zero_hit(xor_only, 0x1010 + step, XOR_REGISTER_LINE) for step in range(10)]
    references += [_zero_hit(mixed, 0x2010 + step, XOR_REGISTER_LINE) for step in range(10)]
    references += [_zero_hit(mixed, 0x2100 - 4 * step, INSTRUCTION_LINE) for step in range(1, 7)]
    result = _find([xor_only, mixed], references, value=0)
    assert result == {
        "total": 1,
        "truncated": False,
        "functions": [_entry(0x2000, "mixed", [0x20FC, 0x20F8, 0x20F4, 0x20F0, 0x20EC, 0x20E8])],
    }
    unfiltered = _find([xor_only, mixed], references, value=0, include_implicit_zero=True)
    assert unfiltered["total"] == 2
    assert unfiltered["functions"][0] == _entry(
        0x1000, "xor_only", [0x1010 + step for step in range(6)], truncated=True
    )


def test_the_address_cap_counts_only_zero_immediates() -> None:
    function = FakeFunction("code", 0x1000, 0x1100)
    references = [_zero_hit(function, 0x1010 + 4 * step, XOR_REGISTER_LINE) for step in range(8)]
    references += [_zero_hit(function, 0x1080 + 4 * step, INSTRUCTION_LINE) for step in range(6)]
    result = _find([function], references, value=0)
    assert result["functions"] == [
        _entry(0x1000, "code", [0x1080 + 4 * step for step in range(6)], truncated=False)
    ]


def test_paging_and_totals_count_only_functions_with_a_kept_hit() -> None:
    noisy = FakeFunction("noisy", 0x1000, 0x1100)
    first = FakeFunction("first", 0x2000, 0x2100)
    second = FakeFunction("second", 0x3000, 0x3100)
    third = FakeFunction("third", 0x4000, 0x4100)
    functions = [noisy, first, second, third]
    references = [
        _zero_hit(noisy, 0x1008, XOR_REGISTER_LINE),
        _zero_hit(first, 0x2008, INSTRUCTION_LINE),
        _zero_hit(second, 0x3008, INSTRUCTION_LINE),
        _zero_hit(noisy, 0x1010, XOR_REGISTER_LINE),
        _zero_hit(third, 0x4008, INSTRUCTION_LINE),
    ]
    assert _find(functions, references, value=0, limit=1, offset=1) == {
        "total": 3,
        "truncated": True,
        "functions": [_entry(0x3000, "second", [0x3008])],
    }
    assert _find(functions, references, value=0, limit=2, offset=1) == {
        "total": 3,
        "truncated": False,
        "functions": [_entry(0x3000, "second", [0x3008]), _entry(0x4000, "third", [0x4008])],
    }
    assert _find(functions, references, value=0, limit=3)["total"] == 3
    assert _find(functions, references, value=0, limit=10, offset=3) == {
        "total": 3,
        "truncated": False,
        "functions": [],
    }


def test_a_dropped_hit_past_a_full_page_does_not_truncate_it() -> None:
    first = FakeFunction("first", 0x2000, 0x2100)
    noisy = FakeFunction("noisy", 0x3000, 0x3100)
    references = [
        _zero_hit(first, 0x2008, INSTRUCTION_LINE),
        _zero_hit(noisy, 0x3008, XOR_REGISTER_LINE),
    ]
    assert _find([first, noisy], references, value=0, limit=1) == {
        "total": 1,
        "truncated": False,
        "functions": [_entry(0x2000, "first", [0x2008])],
    }
    unfiltered = _find([first, noisy], references, value=0, limit=1, include_implicit_zero=True)
    assert unfiltered["truncated"] is True


def test_the_name_filter_and_the_option_combine() -> None:
    kept = FakeFunction("kept_fn", 0x1000, 0x1100)
    other = FakeFunction("other_fn", 0x2000, 0x2100)
    references = [
        _zero_hit(kept, 0x1008, XOR_REGISTER_LINE),
        _zero_hit(other, 0x2008, XOR_REGISTER_LINE),
    ]
    result = _find(
        [kept, other], references, value=0, function_filter="^kept", include_implicit_zero=True
    )
    assert result["functions"] == [_entry(0x1000, "kept_fn", [0x1008])]


def test_include_implicit_zero_is_an_optional_boolean_defaulting_to_false() -> None:
    tool = FakeTool("rex_constant_find", *get_tool("rex_constant_find"))
    properties = tool.input_schema["properties"]
    assert properties["include_implicit_zero"]["type"] == "boolean"
    assert properties["include_implicit_zero"]["default"] is False
    assert "include_implicit_zero" not in tool.input_schema.get("required", [])
