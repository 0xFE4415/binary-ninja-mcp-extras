"""IL and disassembly text tools: HLIL search and batch decompilation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, TypedDict

from binaryninja import mcp

from binja_plugin.tools import (
    _MAX_DISASM_CONTEXT,
    _compile_user_regex,
    _disasm_window,
    _drop,
    _ItemError,
    _name_filter,
    _parse_address_entry,
    _render_function_disassembly,
    _require_address_list,
    _require_analyzed_function,
    _ResolvedFunction,
    _truncate,
    _validate_disasm_window,
    _validate_range,
)

if TYPE_CHECKING:
    from binaryninja.highlevelil import HighLevelILFunction

_MAX_HLIL_GREP_LIMIT = 200
_MAX_HLIL_GREP_FUNCTIONS = 5000

_MAX_HLIL_GREP_CONTEXT = 8
_MAX_DECOMPILE_BATCH = 1024
_MAX_DECOMPILE_LINES = 512

_MAX_DISASM_BATCH = 64
_MAX_DISASM_MANY_LINES = 512
_MAX_DISASM_MANY_TOTAL_LINES = 1024


class _DecompiledFunction(_ResolvedFunction):
    index: int
    lines: list[str]
    truncated: bool


class _DecompileError(TypedDict):
    index: int
    address: str
    error: _ItemError


class _DecompileManyResult(TypedDict):
    functions: list[_DecompiledFunction]
    errors: list[_DecompileError]


class _InstructionLine(TypedDict):
    address: str
    text: str


class _DisasmAtResult(TypedDict):
    function: _ResolvedFunction
    instructions: list[_InstructionLine]
    truncated: bool


class _DisasmError(TypedDict):
    index: int
    address: str
    error: _ItemError


class _DisasmWindow(TypedDict):
    address: str
    index: int
    function: _ResolvedFunction
    instructions: list[_InstructionLine]
    truncated: bool


class _DisasmManyResult(TypedDict):
    windows: list[_DisasmWindow]
    errors: list[_DisasmError]
    truncated: bool
    next_offset: int | None


class _HlilGrepMatch(TypedDict):
    start: str
    name: str
    lines: list[str]


class _HlilGrepResult(TypedDict):
    scanned: int
    truncated: bool
    scan_incomplete: bool
    skipped_no_hlil: int
    functions: list[_HlilGrepMatch]
    next_offset: int | None


def _render_hlil_lines(hlil: HighLevelILFunction | None, max_lines: int) -> tuple[list[str], bool]:
    """Render a function's HLIL to at most ``max_lines`` truncated lines."""
    source_lines = str(hlil).splitlines() if hlil is not None else []
    return [_truncate(line) for line in source_lines[:max_lines]], len(source_lines) > max_lines


def _render_hlil_matches(
    source_lines: list[str],
    matched_indices: list[int],
    context_before: int,
    context_after: int,
) -> list[str]:
    if context_before == 0 and context_after == 0:
        return [_truncate(source_lines[index]) for index in matched_indices[:3]]
    lines: list[str] = []
    for match_index in matched_indices[:3]:
        if lines:
            lines.append("--")
        before = source_lines[max(0, match_index - context_before) : match_index]
        after = source_lines[match_index + 1 : match_index + 1 + context_after]
        lines.extend("  " + _truncate(line) for line in before)
        lines.append("> " + _truncate(source_lines[match_index]))
        lines.extend("  " + _truncate(line) for line in after)
    return lines


@mcp.tool(read_only=True)
def rex_decompile_many(
    call: mcp.ToolCall,
    functions: list[str],
    max_lines: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_DECOMPILE_LINES)] = 200,
) -> _DecompileManyResult:
    """Return each function's signature then HLIL lines; a bad address is a per-item error.

    :param functions: 1 to 1024 address expressions; each result carries its input index.
    :param max_lines: Lines per function, counting the signature line.
    """
    bv = call.binary_view
    max_lines = _validate_range("max_lines", max_lines, 1, _MAX_DECOMPILE_LINES)
    expressions = _require_address_list(functions, _MAX_DECOMPILE_BATCH, "functions")
    rendered: list[_DecompiledFunction] = []
    errors: list[_DecompileError] = []
    for index, expression in enumerate(expressions):
        try:
            address = _parse_address_entry(call, index, expression, "functions")
            resolution = _require_analyzed_function(bv, address)
        except mcp.ToolError as error:
            errors.append(
                {
                    "index": index,
                    "address": _truncate(str(expression)),
                    "error": {"code": error.code, "message": error.message},
                }
            )
            continue
        function = resolution.function
        body, truncated = _render_hlil_lines(function.hlil, max_lines - 1)
        lines = [_truncate(str(function)), *body]
        rendered.append(
            {**resolution.entry, "index": index, "lines": lines, "truncated": truncated}
        )
    return {"functions": rendered, "errors": errors}


@mcp.tool(read_only=True)
def rex_disasm_at(
    call: mcp.ToolCall,
    address: mcp.Address,
    before: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 4,
    after: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 8,
) -> _DisasmAtResult:
    """Return the disassembly lines around an address, with the containing function.

    :param address: Address expression inside the target function.
    :param before: Instructions to include before the anchor.
    :param after: Instructions to include after the anchor.
    """
    bv = call.binary_view
    before, after = _validate_disasm_window(before, after)
    resolution = _require_analyzed_function(bv, address)
    lines = _render_function_disassembly(resolution.function)
    start, end = _disasm_window(lines, address, before, after)
    return {
        "function": resolution.entry,
        "instructions": [
            {"address": hex(line_address), "text": _truncate(text)}
            for line_address, text in lines[start:end]
        ],
        "truncated": start > 0 or end < len(lines),
    }


@mcp.tool(read_only=True)
def rex_disasm_many(
    call: mcp.ToolCall,
    addresses: list[str],
    max_lines: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_DISASM_MANY_LINES)] = 32,
) -> _DisasmManyResult:
    """Batch disassembly windows, e.g. one per VM handler; per-item errors, next_offset resumes.

    :param addresses: 1 to 64 address expressions; next_offset marks the first not returned.
    :param max_lines: Instructions per address, anchored at the last line at or before it.
    """
    bv = call.binary_view
    max_lines = _validate_range("max_lines", max_lines, 1, _MAX_DISASM_MANY_LINES)
    if not isinstance(addresses, list):
        raise mcp.ToolError("invalid_params", "addresses must be a list of address expressions")
    if not 1 <= len(addresses) <= _MAX_DISASM_BATCH:
        raise mcp.ToolError(
            "invalid_params",
            f"addresses must contain between 1 and {_MAX_DISASM_BATCH} address expressions",
        )
    windows: list[_DisasmWindow] = []
    errors: list[_DisasmError] = []
    total_lines = 0
    truncated = False
    next_offset: int | None = None
    for index, address_expression in enumerate(addresses):
        try:
            address = _parse_address_entry(call, index, address_expression, "addresses")
            resolution = _require_analyzed_function(bv, address)
        except mcp.ToolError as error:
            errors.append(
                {
                    "index": index,
                    "address": _truncate(str(address_expression)),
                    "error": {"code": error.code, "message": error.message},
                }
            )
            continue
        lines = _render_function_disassembly(resolution.function)
        start, end = _disasm_window(lines, address, 0, max_lines - 1)
        window = lines[start:end]
        if total_lines + len(window) > _MAX_DISASM_MANY_TOTAL_LINES:
            truncated = True
            next_offset = index
            break
        total_lines += len(window)
        windows.append(
            {
                "address": hex(address),
                "index": index,
                "function": resolution.entry,
                "instructions": [
                    {"address": hex(line_address), "text": _truncate(text)}
                    for line_address, text in window
                ],
                "truncated": end < len(lines),
            }
        )
    return {
        "windows": windows,
        "errors": errors,
        "truncated": truncated,
        "next_offset": next_offset,
    }


@mcp.tool(read_only=True)
def rex_hlil_grep(
    call: mcp.ToolCall,
    regex: str,
    function_filter: str = "",
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_HLIL_GREP_LIMIT)] = 20,
    max_functions: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_HLIL_GREP_FUNCTIONS)] = 2000,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
    context_before: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_HLIL_GREP_CONTEXT)] = 0,
    context_after: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_HLIL_GREP_CONTEXT)] = 0,
) -> _HlilGrepResult:
    """Return functions whose HLIL lines match a regex, with up to 3 matching lines each.

    :param regex: Regular expression applied to every rendered HLIL line.
    :param function_filter: Case-insensitive regex matched against function names.
    :param limit: Maximum matching functions to return.
    :param max_functions: Maximum functions to scan before stopping.
    :param offset: Functions to skip before scanning starts.
    :param context_before: HLIL lines included before each match.
    :param context_after: HLIL lines included after each match.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_HLIL_GREP_LIMIT)
    max_functions = _validate_range("max_functions", max_functions, 0, _MAX_HLIL_GREP_FUNCTIONS)
    offset = _validate_range("offset", offset, 0)
    context_before = _validate_range("context_before", context_before, 0, _MAX_HLIL_GREP_CONTEXT)
    context_after = _validate_range("context_after", context_after, 0, _MAX_HLIL_GREP_CONTEXT)
    matcher = _compile_user_regex("regex", regex)
    name_matcher = _name_filter(function_filter)
    search = matcher.search
    matches: list[_HlilGrepMatch] = []
    scanned = 0
    truncated = False
    scan_incomplete = False
    skipped_no_hlil = 0
    next_offset: int | None = None
    # limit=0 pages nothing out, so the window is full from the first scan.
    window_full = limit == 0
    for index, function in enumerate(_drop(bv.functions, offset), offset):
        if scanned >= max_functions:
            # Budget ran out with functions unscanned: only a past-page match sets `truncated`.
            scan_incomplete = True
            next_offset = index
            break
        if name_matcher is not None and name_matcher.search(function.name) is None:
            continue
        hlil = function.hlil
        if hlil is None:
            skipped_no_hlil += 1
            continue
        scanned += 1
        source_lines = str(hlil).splitlines()
        matched = [line_index for line_index, line in enumerate(source_lines) if search(line)]
        if window_full:
            if matched:
                # One matching function past the page proves more exist; stop scanning there.
                truncated = True
                next_offset = index
                break
        elif matched:
            lines = _render_hlil_matches(source_lines, matched, context_before, context_after)
            matches.append(
                {
                    "start": hex(function.start),
                    "name": _truncate(function.name),
                    "lines": lines,
                }
            )
            window_full = len(matches) >= limit
    return {
        "scanned": scanned,
        "truncated": truncated,
        "scan_incomplete": scan_incomplete,
        "skipped_no_hlil": skipped_no_hlil,
        "functions": matches,
        "next_offset": next_offset,
    }
