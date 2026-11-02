"""IL and disassembly text tools: HLIL search, batch decompilation, and entry discovery."""

from __future__ import annotations

import re
from typing import Annotated, Any

from binaryninja import mcp
from binaryninja.binaryview import BinaryView
from binaryninja.function import Function

from binja_plugin.tools import (
    _MAX_DISASM_CONTEXT,
    _compile_user_regex,
    _disasm_window,
    _drop,
    _function_entry,
    _name_filter,
    _render_function_disassembly,
    _require_analyzed_function,
    _truncate,
    _validate_disasm_window,
    _validate_range,
)

_MAX_HLIL_GREP_LIMIT = 200
_MAX_HLIL_GREP_FUNCTIONS = 5000

# rex_hlil_grep per-match context: bounded so the three-matches-per-function cap keeps
# the echoed lines per function a few dozen at most.
_MAX_HLIL_GREP_CONTEXT = 8
# rex_decompile_many caps: 16 address expressions bound one call's decompilation cost,
# and 400 lines bound the echoed text per function.
_MAX_DECOMPILE_BATCH = 16
_MAX_DECOMPILE_LINES = 400

# rex_quick_main's resolution chain: function symbols first, then the __libc_start_main
# pointer argument of the entry stub, then an explicitly named entry-function fallback.
_MAIN_SYMBOL_NAMES = ("main", "_main")
_MAIN_LIBC_MARKER = "libc_start_main"
_MAIN_FALLBACK_NOTE = (
    "no main symbol and no parsable __libc_start_main pointer in the entry function"
)


def _render_hlil_lines(hlil: Any, max_lines: int) -> tuple[list[str], bool]:
    """Render a function's HLIL to at most ``max_lines`` truncated lines.

    Shared by rex_decompile_many and rex_quick_main so both tools echo exactly the same
    render. The flag reports lines left out by the cap, never clipped text.
    """
    source_lines = str(hlil).splitlines() if hlil is not None else []
    return [_truncate(line) for line in source_lines[:max_lines]], len(source_lines) > max_lines


def _first_call_argument(line: str, marker: str) -> str | None:
    """Return the first argument token of the call following ``marker`` on ``line``."""
    start = line.find("(", line.find(marker))
    if start == -1:
        return None
    argument = line[start + 1 :]
    comma = argument.find(",")
    if comma != -1:
        argument = argument[:comma]
    else:
        closing = argument.find(")")
        if closing == -1:
            return None
        argument = argument[:closing]
    return argument.strip()


def _argument_address(call: mcp.ToolCall, argument: str | None) -> int | None:
    """Resolve a rendered HLIL argument token to an address, or None.

    Rendered pointers embed their address ("0x401234", "*0x401234"); any other token
    goes through the core's address-expression parser, which resolves symbol and
    data-variable names (both verified live).
    """
    if argument is None:
        return None
    hex_match = re.search(r"0x[0-9a-fA-F]+", argument)
    if hex_match is not None:
        return int(hex_match.group(0), 16)
    try:
        return call.parse_address(argument)
    except Exception:
        return None


def _entry_argument_main(
    bv: BinaryView, call: mcp.ToolCall, entry: Function
) -> tuple[Function | None, str | None]:
    """Find main as the __libc_start_main-style pointer argument of the entry function.

    Returns (main, None) on success, or (None, reason) naming what blocked resolution.
    """
    hlil = entry.hlil
    if hlil is None:
        return None, "the entry function has no HLIL yet"
    for line in str(hlil).splitlines():
        if _MAIN_LIBC_MARKER not in line:
            continue
        address = _argument_address(call, _first_call_argument(line, _MAIN_LIBC_MARKER))
        if address is None:
            return None, _MAIN_FALLBACK_NOTE
        functions = bv.get_functions_containing(address)
        if functions:
            return functions[0], None
        return (
            None,
            f"found candidate main address {address:#x} but no analyzed function contains it",
        )
    return None, _MAIN_FALLBACK_NOTE


def _resolve_main(
    bv: BinaryView, call: mcp.ToolCall, entry: Function
) -> tuple[Function | None, str, str | None]:
    """Resolve main: function symbol first, then the entry stub's pointer argument.

    Returns (main, method, note); the note is set only when main could not be resolved
    at all, so the entry-fallback response can say why.
    """
    if entry.name in _MAIN_SYMBOL_NAMES:
        return entry, "symbol", None
    for name in _MAIN_SYMBOL_NAMES:
        candidates = sorted(bv.get_functions_by_name(name), key=lambda function: function.start)
        if candidates:
            return candidates[0], "symbol", None
    main, note = _entry_argument_main(bv, call, entry)
    if main is not None:
        return main, "entry-arg", note
    return None, "entry-fallback", note


@mcp.tool(read_only=True)
def rex_decompile_many(
    call: mcp.ToolCall,
    functions: list[str],
    max_lines: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_DECOMPILE_LINES)] = 200,
) -> dict[str, object]:
    """Batch decompilation for triage.

    Renders the HLIL of up to 16 functions in one call. Every address expression is
    resolved and checked against the analyzed functions before anything is rendered, so
    one invalid or unanalyzed entry rejects the whole call: a result is always complete
    or absent, never partial. HLIL rendering costs tens of milliseconds per function the
    first time, which is what the batch cap bounds.

    :param functions: Address expressions of the functions to render, in output order;
        1 to 16 entries.
    :param max_lines: HLIL lines to render per function (1 to 400).
    """
    bv = call.binary_view
    max_lines = _validate_range("max_lines", max_lines, 1, _MAX_DECOMPILE_LINES)
    if not isinstance(functions, list):
        raise mcp.ToolError("invalid_params", "functions must be a list of address expressions")
    if not 1 <= len(functions) <= _MAX_DECOMPILE_BATCH:
        raise mcp.ToolError(
            "invalid_params",
            f"functions must contain between 1 and {_MAX_DECOMPILE_BATCH} address expressions",
        )
    # Resolve and check every entry before rendering anything, so a bad entry anywhere
    # in the batch cannot leave a partial result behind.
    resolved: list[Function] = []
    for index, entry in enumerate(functions):
        if not isinstance(entry, str):
            raise mcp.ToolError(
                "invalid_params", f"functions[{index}] must be a string address expression"
            )
        try:
            address = call.parse_address(entry)
        except Exception as error:
            raise mcp.ToolError(
                "invalid_params", f"bad address expression '{_truncate(entry)}': {error}"
            ) from None
        resolved.append(_require_analyzed_function(bv, address))
    rendered: list[dict[str, object]] = []
    for function in resolved:
        lines, truncated = _render_hlil_lines(function.hlil, max_lines)
        rendered.append({**_function_entry(function), "lines": lines, "truncated": truncated})
    return {"functions": rendered}


@mcp.tool(read_only=True)
def rex_disasm_at(
    call: mcp.ToolCall,
    address: mcp.Address,
    before: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 4,
    after: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 8,
) -> dict[str, object]:
    """Address-anchored disassembly window.

    The window is anchored at the instruction containing ``address`` and clipped at the
    edges of the containing function: fewer instructions coming back means the function
    ends there, not an error. An address outside every analyzed function is rejected
    rather than snapped to the nearest one. The call renders the containing function's
    disassembly once, so the cost scales with that function.

    :param address: Address expression inside the target function; accepts hex like
        0x401000, symbols, and Binary Ninja expressions.
    :param before: Instructions to include before the anchor (0 to 64).
    :param after: Instructions to include after the anchor (0 to 64).
    """
    bv = call.binary_view
    before, after = _validate_disasm_window(before, after)
    function = _require_analyzed_function(bv, address)
    lines = _render_function_disassembly(function)
    start, end = _disasm_window(lines, address, before, after)
    return {
        "function": _function_entry(function),
        "instructions": [
            {"address": hex(line_address), "text": _truncate(text)}
            for line_address, text in lines[start:end]
        ],
        "truncated": start > 0 or end < len(lines),
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
) -> dict[str, object]:
    """Search rendered HLIL text across functions with a regular expression.

    Regular expressions run on Python's ``re`` with no timeout, so a pattern with
    catastrophic backtracking can stall the scan. Each function reports at most the
    first 3 matching HLIL lines.

    With ``context_before``/``context_after`` each match comes back wrapped in that
    many surrounding HLIL lines: the matched line is prefixed with ``"> "`` and the
    context lines with two spaces, and consecutive windows are separated by ``"--"`` so
    overlapping context ranges stay unambiguous. Function edges truncate the window;
    the caps on matches per function and on echoed line length are unchanged.

    Rendering HLIL is the dominant cost: tens of milliseconds per function the first
    time a function's HLIL is generated. A single invocation never renders more than
    ``max_functions`` functions; page through a larger database by passing the
    ``next_offset`` of the previous result as ``offset`` until ``truncated`` is false.

    :param regex: Regular expression applied to every rendered HLIL line.
    :param function_filter: Case-insensitive regular expression matched against function names.
    :param limit: Maximum number of matching functions to return (0 to 200).
    :param max_functions: Maximum number of functions to scan before stopping (0 to 5000).
    :param offset: Number of functions to skip before scanning starts (>= 0).
    :param context_before: HLIL lines to include before each match (0 to 8).
    :param context_after: HLIL lines to include after each match (0 to 8).
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_HLIL_GREP_LIMIT)
    max_functions = _validate_range("max_functions", max_functions, 0, _MAX_HLIL_GREP_FUNCTIONS)
    offset = _validate_range("offset", offset, 0)
    context_before = _validate_range("context_before", context_before, 0, _MAX_HLIL_GREP_CONTEXT)
    context_after = _validate_range("context_after", context_after, 0, _MAX_HLIL_GREP_CONTEXT)
    matcher = _compile_user_regex(regex)
    name_matcher = _name_filter(function_filter)
    matches: list[dict[str, object]] = []
    scanned = 0
    truncated = False
    next_offset: int | None = None
    for index, function in enumerate(_drop(bv.functions, offset), offset):
        if len(matches) >= limit or scanned >= max_functions:
            truncated = True
            next_offset = index
            break
        if name_matcher is not None and name_matcher.search(function.name) is None:
            continue
        hlil = function.hlil
        if hlil is None:
            continue
        scanned += 1
        source_lines = str(hlil).splitlines()
        matched = [
            line_index for line_index, line in enumerate(source_lines) if matcher.search(line)
        ]
        if matched:
            if context_before == 0 and context_after == 0:
                lines = [_truncate(source_lines[match_index]) for match_index in matched[:3]]
            else:
                # "--" keeps windows apart even when their context ranges overlap.
                lines = []
                for match_index in matched[:3]:
                    if lines:
                        lines.append("--")
                    before = source_lines[max(0, match_index - context_before) : match_index]
                    after = source_lines[match_index + 1 : match_index + 1 + context_after]
                    lines.extend("  " + _truncate(line) for line in before)
                    lines.append("> " + _truncate(source_lines[match_index]))
                    lines.extend("  " + _truncate(line) for line in after)
            matches.append(
                {
                    "start": hex(function.start),
                    "name": _truncate(function.name),
                    "lines": lines,
                }
            )
    return {
        "scanned": scanned,
        "truncated": truncated,
        "functions": matches,
        "next_offset": next_offset,
    }


@mcp.tool(read_only=True)
def rex_quick_main(
    call: mcp.ToolCall,
    max_lines: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_DECOMPILE_LINES)] = 200,
) -> dict[str, object]:
    """One-call fast contact: the entry point, main, and main's HLIL.

    main is resolved from a function symbol named main/_main (the entry function itself
    or a symbol lookup), else from the __libc_start_main-style pointer argument parsed
    out of the entry function's HLIL — the shape a stripped binary's entry stub renders
    for the main pointer. HLIL is generated lazily per function, so this works while
    whole-binary analysis is still running in the background. When neither resolves,
    the response says so explicitly (method "entry-fallback" plus a note) and renders
    the entry function's HLIL instead; it never presents the entry function as main.

    :param max_lines: HLIL lines to render (1 to 400).
    """
    bv = call.binary_view
    max_lines = _validate_range("max_lines", max_lines, 1, _MAX_DECOMPILE_LINES)
    entry_point = bv.entry_point
    functions = bv.get_functions_containing(entry_point)
    if not functions:
        raise mcp.ToolError(
            "no_function", f"no analyzed function contains the entry point {entry_point:#x}"
        )
    main, method, note = _resolve_main(bv, call, functions[0])
    function = main if main is not None else functions[0]
    lines, truncated = _render_hlil_lines(function.hlil, max_lines)
    return {
        "entry_point": hex(entry_point),
        "method": method,
        "main": hex(main.start) if main is not None else None,
        "note": note,
        "function": _function_entry(function),
        "lines": lines,
        "truncated": truncated,
    }
