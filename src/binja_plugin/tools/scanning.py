"""Memory and constant scanning: hex byte patterns and immediate-constant references."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Annotated

from binaryninja import mcp

from binja_plugin.hexpattern import HexPatternError, compile_hex_pattern
from binja_plugin.tools import (
    _MAX_LIMIT,
    _drop,
    _iter_pattern_matches,
    _name_filter,
    _paginate,
    _resolve_section,
    _truncate,
    _validate_range,
)

# rex_constant_find matches displayed constants, which are at most 64-bit values.
_MAX_CONSTANT_VALUE = 2**64 - 1

# Raw pattern-string cap for rex_data_find: bounds the regex compile and the per-chunk
# read inflation (read_size grows with the pattern length) before any of that happens.
_MAX_PATTERN_CHARS = 8192

# rex_find_functions_by_pattern example matches per function: triage wants a handful of
# hit addresses; rex_data_find already returns full match lists.
_MAX_FIND_FUNCTIONS_EXAMPLES = 5


def _compile_pattern(pattern: str) -> tuple[re.Pattern[bytes], int]:
    if len(pattern) > _MAX_PATTERN_CHARS:
        raise mcp.ToolError("pattern_too_large", f"pattern exceeds {_MAX_PATTERN_CHARS} characters")
    try:
        return compile_hex_pattern(pattern)
    except HexPatternError as exc:
        raise mcp.ToolError("invalid_pattern", str(exc)) from None


@dataclass
class _FunctionHits:
    name: str
    match_count: int = 0
    addresses: list[str] = field(default_factory=list)


@mcp.tool(read_only=True)
def rex_constant_find(
    call: mcp.ToolCall,
    value: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_CONSTANT_VALUE)],
    function_filter: str = "",
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """Find functions whose rendered instructions reference an immediate constant value.

    :param value: Immediate value to search for, compared against displayed constants.
    :param function_filter: Case-insensitive regex matched against function names.
    :param limit: Maximum matching functions to return.
    :param offset: Matching functions to skip before collecting results.
    """
    bv = call.binary_view
    value = _validate_range("value", value, 0, _MAX_CONSTANT_VALUE)
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    name_matcher = _name_filter(function_filter)
    functions: list[dict[str, object]] = []
    truncated = False
    abort = False

    def keep_scanning(current: int, total: int) -> bool:
        return not abort

    matched = 0
    current_start: int | None = None
    current_addresses: list[str] = []
    for address, line in bv.find_all_constant(bv.start, bv.end, value, progress_func=keep_scanning):
        function = line.function
        if function is None:
            continue
        if name_matcher is not None and name_matcher.search(function.name) is None:
            continue
        if function.start != current_start:
            matched += 1
            if matched > offset + limit:
                # One match past the requested window proves more functions exist.
                truncated = True
                abort = True
                break
            current_start = int(function.start)
            current_addresses = []
            entry: dict[str, object] = {
                "start": hex(function.start),
                "name": _truncate(function.name),
                "addresses": current_addresses,
            }
            if matched > offset:
                functions.append(entry)
        if len(current_addresses) < 6:
            current_addresses.append(hex(address))
    return {"truncated": truncated, "functions": functions}


@mcp.tool(read_only=True)
def rex_data_find(
    call: mcp.ToolCall,
    pattern: str,
    section: str | None = None,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """Find all occurrences of a hex byte pattern in mapped memory.

    :param pattern: Hex byte pattern, e.g. "48 8b ?? 05"; "??" matches any single byte.
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
) -> dict[str, object]:
    """Which functions contain a byte pattern.

    :param pattern: Hex byte pattern, e.g. "48 8b ?? 05"; "??" matches any single byte.
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
        function = containing[0]
        entry = hits.get(function.start)
        if entry is None:
            if len(hits) >= offset + limit:
                # The first matching function past the window proves more exist; stop
                # the scan there instead of counting the rest.
                truncated = True
                break
            entry = hits[function.start] = _FunctionHits(_truncate(function.name))
        entry.match_count += 1
        if len(entry.addresses) < _MAX_FIND_FUNCTIONS_EXAMPLES:
            entry.addresses.append(hex(address))
    functions = [
        {
            "start": hex(start),
            "name": entry.name,
            "match_count": entry.match_count,
            "addresses": entry.addresses,
        }
        for start, entry in _drop(hits.items(), offset)
    ]
    return {"truncated": truncated, "functions": functions}
