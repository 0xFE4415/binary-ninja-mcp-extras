"""Memory and constant scanning: hex byte patterns and immediate-constant references."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Annotated, TypedDict

from binaryninja import mcp
from binaryninja.enums import InstructionTextTokenType

from binja_plugin.hexpattern import HexPatternError, compile_hex_pattern
from binja_plugin.tools import (
    _MAX_LIMIT,
    _drop,
    _function_order,
    _iter_pattern_matches,
    _name_filter,
    _paginate,
    _resolve_section,
    _truncate,
    _validate_range,
)

if TYPE_CHECKING:
    from binaryninja.function import InstructionTextToken

# rex_constant_find matches displayed constants, which are at most 64-bit values.
_MAX_CONSTANT_VALUE = 2**64 - 1

# InstructionTextToken.operand for a token that belongs to no operand, such as an annotation.
_NO_OPERAND = 0xFFFFFFFF

_IMMEDIATE_TOKEN_TYPES = (
    InstructionTextTokenType.IntegerToken,
    InstructionTextTokenType.PossibleAddressToken,
)

# Bounds the regex compile and the per-chunk read size, which grows with the pattern length.
_MAX_PATTERN_CHARS = 8192

# One extra address is collected so `addresses_truncated` tells an exact cap from clipped examples.
_MAX_FIND_FUNCTIONS_EXAMPLES = 5

# A hot constant in one function stays bounded; one extra address is collected as above.
_MAX_CONSTANT_ADDRESSES = 6


def _compile_pattern(pattern: str) -> tuple[re.Pattern[bytes], int]:
    if len(pattern) > _MAX_PATTERN_CHARS:
        raise mcp.ToolError("pattern_too_large", f"pattern exceeds {_MAX_PATTERN_CHARS} characters")
    try:
        return compile_hex_pattern(pattern)
    except HexPatternError as exc:
        raise mcp.ToolError("invalid_pattern", str(exc)) from None


class _ConstantFunction(TypedDict):
    start: str
    name: str
    addresses: list[str]
    addresses_truncated: bool


class _ConstantFindResult(TypedDict):
    total: int
    truncated: bool
    functions: list[_ConstantFunction]


class _DataFindResult(TypedDict):
    total: int
    truncated: bool
    matches: list[str]


class _PatternFunction(TypedDict):
    start: str
    name: str
    match_count: int
    addresses: list[str]
    addresses_truncated: bool


class _FindFunctionsResult(TypedDict):
    total: int
    truncated: bool
    functions: list[_PatternFunction]


@dataclass(slots=True)
class _FunctionHits:
    name: str
    match_count: int = 0
    addresses: list[str] = field(default_factory=list)


def _has_zero_immediate(tokens: list[InstructionTextToken]) -> bool:
    for token in tokens:
        if token.operand == _NO_OPERAND or token.type not in _IMMEDIATE_TOKEN_TYPES:
            continue
        if token.value == 0:
            return True
    return False


@mcp.tool(read_only=True)
def rex_constant_find(
    call: mcp.ToolCall,
    value: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_CONSTANT_VALUE)],
    function_filter: str = "",
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
    include_implicit_zero: bool = False,
) -> _ConstantFindResult:
    """Find functions using an immediate constant (a magic value) in disassembly, not raw bytes.

    :param value: Immediate value to search for, compared against displayed constants.
    :param function_filter: Case-insensitive regex matched against function names.
    :param limit: Maximum matching functions to return.
    :param offset: Matching functions to skip before collecting results.
    :param include_implicit_zero: With value 0, also return hits such as xor eax, eax.
    """
    bv = call.binary_view
    value = _validate_range("value", value, 0, _MAX_CONSTANT_VALUE)
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    name_matcher = _name_filter(function_filter)
    truncated = False
    abort = False

    def keep_scanning(current: int, total: int) -> bool:
        return not abort

    groups: dict[int, _FunctionHits] = {}
    for address, line in bv.find_all_constant(bv.start, bv.end, value, progress_func=keep_scanning):
        function = line.function
        if function is None:
            continue
        tokens = line.contents.tokens
        if not any(token.type == InstructionTextTokenType.InstructionToken for token in tokens):
            continue
        if value == 0 and not include_implicit_zero and not _has_zero_immediate(tokens):
            continue
        if name_matcher is not None and name_matcher.search(function.name) is None:
            continue
        start = int(function.start)
        group = groups.get(start)
        if group is None:
            if len(groups) >= offset + limit:
                # One match past the requested window proves more functions exist.
                truncated = True
                abort = True
                break
            group = groups[start] = _FunctionHits(_truncate(function.name))
        address_text = hex(address)
        if address_text not in group.addresses and len(group.addresses) <= _MAX_CONSTANT_ADDRESSES:
            group.addresses.append(address_text)
    functions: list[_ConstantFunction] = [
        {
            "start": hex(start),
            "name": group.name,
            "addresses": group.addresses[:_MAX_CONSTANT_ADDRESSES],
            "addresses_truncated": len(group.addresses) > _MAX_CONSTANT_ADDRESSES,
        }
        for start, group in _drop(groups.items(), offset)
    ]
    # Count seen, like _paginate: exact when the scan finished, a lower bound once truncated.
    return {"total": len(groups) + int(truncated), "truncated": truncated, "functions": functions}


@mcp.tool(read_only=True)
def rex_data_find(
    call: mcp.ToolCall,
    pattern: Annotated[str, mcp.Schema({"type": "string", "maxLength": _MAX_PATTERN_CHARS})],
    section: str | None = None,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> _DataFindResult:
    """Find all occurrences of a hex byte pattern in mapped memory.

    :param pattern: Hex byte pattern, e.g. "48 8b ?? 05"; each byte is 2 ASCII hex digits or "??".
    :param section: Only search within this section.
    :param limit: Maximum matches to return.
    :param offset: Matches to skip before collecting results.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    matcher, pattern_length = _compile_pattern(pattern)
    bounds = _resolve_section(bv, section) if section is not None else None
    addresses = (
        hex(address) for address in _iter_pattern_matches(bv, matcher, pattern_length, bounds)
    )
    matches, total, truncated = _paginate(addresses, offset, limit)
    return {"total": total, "truncated": truncated, "matches": matches}


@mcp.tool(read_only=True)
def rex_find_functions_by_pattern(
    call: mcp.ToolCall,
    pattern: str,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> _FindFunctionsResult:
    """Which functions contain a byte pattern; hit counts rank use of an instruction encoding.

    :param pattern: Hex byte pattern, e.g. "48 8b ?? 05"; each byte is 2 ASCII hex digits or "??".
    :param limit: Maximum matching functions to return.
    :param offset: Matching functions to skip before collecting results.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    matcher, pattern_length = _compile_pattern(pattern)
    hits: dict[int, _FunctionHits] = {}
    truncated = False
    get_functions_containing = bv.get_functions_containing
    for address in _iter_pattern_matches(bv, matcher, pattern_length):
        containing = get_functions_containing(address)
        if not containing:
            continue
        function = min(containing, key=_function_order)
        entry = hits.get(function.start)
        if entry is None:
            if len(hits) >= offset + limit:
                # The first matching function past the window proves more exist; stop scanning.
                truncated = True
                break
            entry = hits[function.start] = _FunctionHits(_truncate(function.name))
        entry.match_count += 1
        if len(entry.addresses) <= _MAX_FIND_FUNCTIONS_EXAMPLES:
            entry.addresses.append(hex(address))
    functions: list[_PatternFunction] = [
        {
            "start": hex(start),
            "name": entry.name,
            "match_count": entry.match_count,
            "addresses": entry.addresses[:_MAX_FIND_FUNCTIONS_EXAMPLES],
            "addresses_truncated": len(entry.addresses) > _MAX_FIND_FUNCTIONS_EXAMPLES,
        }
        for start, entry in _drop(hits.items(), offset)
    ]
    # Count seen, like _paginate: exact when the scan finished, a lower bound once truncated.
    return {"total": len(hits) + int(truncated), "truncated": truncated, "functions": functions}
