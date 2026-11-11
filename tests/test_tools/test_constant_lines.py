from __future__ import annotations

from typing import Any

import pytest
from helpers import _call, get_tool
from helpers_view import (
    ANNOTATED_INSTRUCTION_LINE,
    CASE_LINE,
    CONTINUATION_LINE,
    FALLS_THROUGH_LINE,
    FUNCTION_HEADER_LINE,
    INSTRUCTION_LINE,
    FakeArchitecture,
    FakeBinaryView,
    FakeConstantReference,
    FakeFunction,
    FakeInstructionTextTokenType,
    FakeLineToken,
)


def _entry(start: int, name: str, addresses: list[int]) -> dict[str, Any]:
    return {
        "start": hex(start),
        "name": name,
        "addresses": [hex(address) for address in addresses],
        "addresses_truncated": False,
    }


def _find(
    functions: list[FakeFunction], references: list[FakeConstantReference], **options: Any
) -> dict[str, Any]:
    _, find = get_tool("rex_constant_find")
    view = FakeBinaryView(functions=functions, constant_references=references)
    return find(_call(view), **options)


@pytest.mark.parametrize("include", [False, True], ids=["filtering", "including"])
def test_value_zero_counts_only_functions_with_an_instruction_line(include: bool) -> None:
    header_only = FakeFunction("header_only", 0x1000, 0x1100)
    continuation_only = FakeFunction("continuation_only", 0x2000, 0x2100)
    real = FakeFunction("real", 0x3000, 0x3100)
    result = _find(
        [header_only, continuation_only, real],
        [
            (0, 0x1000, header_only, FUNCTION_HEADER_LINE),
            (0, 0x2000, continuation_only, CONTINUATION_LINE),
            (0, 0x3010, real),
        ],
        value=0,
        include_non_operand_hits=include,
    )
    assert result == {
        "total": 1,
        "truncated": False,
        "functions": [_entry(0x3000, "real", [0x3010])],
    }


@pytest.mark.parametrize("include", [False, True], ids=["filtering", "including"])
def test_value_zero_lists_only_the_instruction_addresses_of_a_function(include: bool) -> None:
    function = FakeFunction("sub_4000", 0x4000, 0x4100)
    result = _find(
        [function],
        [
            (0, 0x4000, function, FUNCTION_HEADER_LINE),
            (0, 0x4010, function),
            (0, 0x4040, function, CONTINUATION_LINE),
            (0, 0x4060, function),
        ],
        value=0,
        include_non_operand_hits=include,
    )
    assert result["functions"] == [_entry(0x4000, "sub_4000", [0x4010, 0x4060])]


@pytest.mark.parametrize("include", [False, True], ids=["filtering", "including"])
def test_a_header_and_an_instruction_at_the_same_address_count_as_the_instruction(
    include: bool,
) -> None:
    function = FakeFunction("sub_4000", 0x4000, 0x4100)
    header_and_instruction = _find(
        [function],
        [(0, 0x4000, function, FUNCTION_HEADER_LINE), (0, 0x4000, function)],
        value=0,
        include_non_operand_hits=include,
    )
    assert header_and_instruction["functions"] == [_entry(0x4000, "sub_4000", [0x4000])]
    header_only = _find(
        [function],
        [(0, 0x4000, function, FUNCTION_HEADER_LINE)],
        value=0,
        include_non_operand_hits=include,
    )
    assert header_only == {"total": 0, "truncated": False, "functions": []}


@pytest.mark.parametrize(
    ("line", "value", "include"),
    [
        (FUNCTION_HEADER_LINE, 0, False),
        (FUNCTION_HEADER_LINE, 0, True),
        (CONTINUATION_LINE, 0, False),
        (CONTINUATION_LINE, 0, True),
        (CASE_LINE, 0, False),
        (CASE_LINE, 0, True),
        ((), 0, True),
        (FALLS_THROUGH_LINE, 0x422434, False),
        (CASE_LINE, 0x114, False),
        ((), 0x114, False),
    ],
    ids=[
        "header",
        "header-included",
        "continuation",
        "continuation-included",
        "case-zero",
        "case-zero-included",
        "no-tokens-included",
        "falls-through",
        "case-0x114",
        "no-tokens",
    ],
)
def test_a_line_without_an_instruction_token_never_counts_for_any_value(
    line: tuple[FakeLineToken, ...], value: int, include: bool
) -> None:
    function = FakeFunction("noise", 0x5000, 0x5100)
    options = {"include_non_operand_hits": True} if include else {}
    result = _find([function], [(value, 0x5000, function, line)], value=value, **options)
    assert result == {"total": 0, "truncated": False, "functions": []}


@pytest.mark.parametrize(
    "line",
    [
        INSTRUCTION_LINE,
        ANNOTATED_INSTRUCTION_LINE,
        (FakeLineToken(FakeInstructionTextTokenType.InstructionToken, "nop"),),
        (
            FakeLineToken(FakeInstructionTextTokenType.AddressSeparatorToken),
            FakeLineToken(FakeInstructionTextTokenType.TextToken, "  "),
            FakeLineToken(FakeInstructionTextTokenType.InstructionToken, "ret"),
        ),
    ],
    ids=["compare", "annotated", "only-the-mnemonic", "mnemonic-last"],
)
def test_a_line_with_an_instruction_token_counts_wherever_the_token_sits(
    line: tuple[FakeLineToken, ...],
) -> None:
    function = FakeFunction("code", 0x5000, 0x5100)
    result = _find(
        [function], [(0, 0x5010, function, line)], value=0, include_non_operand_hits=True
    )
    assert result["functions"] == [_entry(0x5000, "code", [0x5010])]


def test_nonzero_values_keep_their_instruction_hits_and_lose_only_the_noise() -> None:
    caller = FakeFunction("caller", 0x6000, 0x6100)
    fallthrough = FakeFunction("fallthrough", 0x7000, 0x7100)
    result = _find(
        [caller, fallthrough],
        [
            (0x422434, 0x6004, caller),
            (0x422434, 0x7040, fallthrough, FALLS_THROUGH_LINE),
            (0x422434, 0x6008, caller),
        ],
        value=0x422434,
    )
    assert result == {
        "total": 1,
        "truncated": False,
        "functions": [_entry(0x6000, "caller", [0x6004, 0x6008])],
    }


@pytest.mark.parametrize("include", [False, True], ids=["filtering", "including"])
def test_noise_lines_take_no_slot_in_the_page_or_the_total(include: bool) -> None:
    noisy = FakeFunction("noisy", 0x1000, 0x1100)
    first = FakeFunction("first", 0x2000, 0x2100)
    second = FakeFunction("second", 0x3000, 0x3100)
    functions = [noisy, first, second]
    references: list[FakeConstantReference] = [
        (0, 0x1000, noisy, FUNCTION_HEADER_LINE),
        (0, 0x2008, first),
        (0, 0x3008, second),
    ]
    options = {"include_non_operand_hits": include}
    assert _find(functions, references, value=0, limit=1, **options) == {
        "total": 2,
        "truncated": True,
        "functions": [_entry(0x2000, "first", [0x2008])],
    }
    assert _find(functions, references, value=0, limit=1, offset=1, **options) == {
        "total": 2,
        "truncated": False,
        "functions": [_entry(0x3000, "second", [0x3008])],
    }
    assert _find(functions, references, value=0, limit=2, **options) == {
        "total": 2,
        "truncated": False,
        "functions": [_entry(0x2000, "first", [0x2008]), _entry(0x3000, "second", [0x3008])],
    }


@pytest.mark.parametrize("include", [False, True], ids=["filtering", "including"])
def test_the_name_filter_still_applies_to_instruction_lines(include: bool) -> None:
    kept = FakeFunction("kept_fn", 0x1000, 0x1100)
    dropped = FakeFunction("dropped_fn", 0x2000, 0x2100)
    result = _find(
        [kept, dropped],
        [(0, 0x1008, kept), (0, 0x2008, dropped)],
        value=0,
        function_filter="^kept",
        include_non_operand_hits=include,
    )
    assert result["functions"] == [_entry(0x1000, "kept_fn", [0x1008])]


@pytest.mark.parametrize("include", [False, True], ids=["filtering", "including"])
def test_a_line_outside_any_function_is_skipped_even_with_an_instruction_token(
    include: bool,
) -> None:
    result = _find([], [(0, 0x9000, None)], value=0, include_non_operand_hits=include)
    assert result == {"total": 0, "truncated": False, "functions": []}


def test_functions_with_the_same_start_on_different_architectures_stay_apart() -> None:
    armv7 = FakeFunction("armv7_copy", 0x1000, 0x1008, arch=FakeArchitecture("armv7"))
    thumb = FakeFunction("thumb_copy", 0x1000, 0x1100, arch=FakeArchitecture("thumb2"))
    references: list[FakeConstantReference] = [
        (0x20, 0x1002, armv7),
        (0x20, 0x1010, thumb),
        (0x20, 0x1004, armv7),
    ]
    assert _find([armv7, thumb], references, value=0x20) == {
        "total": 2,
        "truncated": False,
        "functions": [
            _entry(0x1000, "armv7_copy", [0x1002, 0x1004]),
            _entry(0x1000, "thumb_copy", [0x1010]),
        ],
    }
    assert _find([armv7, thumb], references, value=0x20, limit=1, offset=1) == {
        "total": 2,
        "truncated": False,
        "functions": [_entry(0x1000, "thumb_copy", [0x1010])],
    }
    assert _find([armv7, thumb], references, value=0x20, limit=1) == {
        "total": 2,
        "truncated": True,
        "functions": [_entry(0x1000, "armv7_copy", [0x1002])],
    }
