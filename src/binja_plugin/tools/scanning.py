"""Memory and constant scanning: hex byte patterns and immediate-constant references."""

from __future__ import annotations

import re
import string
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

_OPERAND_VALUE_TOKEN_TYPES = (
    InstructionTextTokenType.IntegerToken,
    InstructionTextTokenType.PossibleAddressToken,
    InstructionTextTokenType.CodeRelativeAddressToken,
    InstructionTextTokenType.FloatingPointToken,
    InstructionTextTokenType.CharacterConstantToken,
    InstructionTextTokenType.EnumerationMemberToken,
    InstructionTextTokenType.CodeSymbolToken,
    InstructionTextTokenType.DataSymbolToken,
    InstructionTextTokenType.ImportToken,
    InstructionTextTokenType.ExternalSymbolToken,
)

_MAX_HEX_DIGITS = 16

_CONSTANT_VALUE_SCHEMA = {
    "type": ["integer", "string"],
    "minimum": 0,
    "maximum": _MAX_CONSTANT_VALUE,
    "pattern": f"^0[xX][0-9a-fA-F]{{1,{_MAX_HEX_DIGITS}}}$",
}

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


def _parse_constant_value(value: int | str) -> int:
    # bool is an int subclass, and the mcp layer passes this schema-typed value through unchecked.
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise mcp.ToolError("invalid_params", "Expected integer or hex string parameter 'value'")
    if not isinstance(value, str):
        return _validate_range("value", value, 0, _MAX_CONSTANT_VALUE)
    if value[:2] not in ("0x", "0X"):
        raise mcp.ToolError("invalid_params", "Invalid hex parameter 'value': must start with 0x")
    digits = value[2:]
    if not digits:
        raise mcp.ToolError(
            "invalid_params", "Invalid hex parameter 'value': needs at least one hex digit after 0x"
        )
    if not all(character in string.hexdigits for character in digits):
        raise mcp.ToolError(
            "invalid_params",
            "Invalid hex parameter 'value': may contain only hex digits after 0x",
        )
    if len(digits) > _MAX_HEX_DIGITS:
        raise mcp.ToolError(
            "invalid_params",
            f"Invalid hex parameter 'value': may have at most {_MAX_HEX_DIGITS} hex digits "
            "(64 bits)",
        )
    return int(digits, 16)


def _reject_non_operand_option_without_zero(constant: int, include_non_operand_hits: bool) -> None:
    if include_non_operand_hits and constant != 0:
        raise mcp.ToolError(
            "invalid_params",
            "Invalid boolean parameter 'include_non_operand_hits': only allowed with value 0",
        )


def _has_zero_operand(tokens: list[InstructionTextToken]) -> bool:
    operand_tokens = [token for token in tokens if token.operand != _NO_OPERAND]
    for token in operand_tokens:
        if token.type in _OPERAND_VALUE_TOKEN_TYPES and token.value == 0:
            return True
    # Without operand indexes the line cannot be judged, so keep it.
    return not operand_tokens


@mcp.tool(read_only=True)
def rex_constant_find(
    call: mcp.ToolCall,
    value: Annotated[int | str, mcp.Schema(_CONSTANT_VALUE_SCHEMA)],
    function_filter: str = "",
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
    include_non_operand_hits: bool = False,
) -> _ConstantFindResult:
    """Find functions using an immediate constant (a magic value) in disassembly, not raw bytes.

    :param value: Integer or 0x hex string (exact above 2^53) to find in displayed constants.
    :param function_filter: Case-insensitive regex matched against function names.
    :param limit: Maximum matching functions to return.
    :param offset: Matching functions to skip before collecting results.
    :param include_non_operand_hits: With value 0, also keep hits like xor eax, eax.
    """
    bv = call.binary_view
    constant = _parse_constant_value(value)
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    _reject_non_operand_option_without_zero(constant, include_non_operand_hits)
    name_matcher = _name_filter(function_filter)
    truncated = False
    abort = False

    def keep_scanning(current: int, total: int) -> bool:
        return not abort

    groups: dict[tuple[int, str], _FunctionHits] = {}
    for address, line in bv.find_all_constant(
        bv.start, bv.end, constant, progress_func=keep_scanning
    ):
        function = line.function
        if function is None:
            continue
        tokens = line.contents.tokens
        if not any(token.type == InstructionTextTokenType.InstructionToken for token in tokens):
            continue
        if constant == 0 and not include_non_operand_hits and not _has_zero_operand(tokens):
            continue
        if name_matcher is not None and name_matcher.search(function.name) is None:
            continue
        key = (int(function.start), function.arch.name)
        group = groups.get(key)
        if group is None:
            if len(groups) >= offset + limit:
                # One match past the requested window proves more functions exist.
                truncated = True
                abort = True
                break
            group = groups[key] = _FunctionHits(_truncate(function.name))
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
        for (start, _), group in _drop(groups.items(), offset)
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
    hits: dict[tuple[int, str], _FunctionHits] = {}
    truncated = False
    get_functions_containing = bv.get_functions_containing
    for address in _iter_pattern_matches(bv, matcher, pattern_length):
        containing = get_functions_containing(address)
        if not containing:
            continue
        function = min(containing, key=_function_order)
        key = (int(function.start), function.arch.name)
        entry = hits.get(key)
        if entry is None:
            if len(hits) >= offset + limit:
                # The first matching function past the window proves more exist; stop scanning.
                truncated = True
                break
            entry = hits[key] = _FunctionHits(_truncate(function.name))
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
        for (start, _), entry in _drop(hits.items(), offset)
    ]
    # Count seen, like _paginate: exact when the scan finished, a lower bound once truncated.
    return {"total": len(hits) + int(truncated), "truncated": truncated, "functions": functions}
