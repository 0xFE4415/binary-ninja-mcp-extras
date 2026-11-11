"""IL and disassembly text tools: HLIL search, batch decompilation, and entry discovery."""

from __future__ import annotations

import re
from itertools import takewhile
from typing import TYPE_CHECKING, Annotated, Literal, TypedDict

from binaryninja import mcp
from binaryninja.binaryview import BinaryView
from binaryninja.function import Function
from binaryninja.highlevelil import HighLevelILConstPtr, HighLevelILTailcall

from binja_plugin.tools import (
    _MAX_DISASM_CONTEXT,
    _compile_user_regex,
    _disasm_window,
    _drop,
    _ItemError,
    _missing_il_message,
    _name_filter,
    _parse_address_entry,
    _render_function_disassembly,
    _require_analyzed_function,
    _Resolution,
    _resolve_address_batch,
    _resolve_containing,
    _resolved_entry,
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

_MAX_TAILCALL_HOPS = 8
_MAIN_SYMBOL_NAMES = ("main", "_main")
_MAIN_LIBC_MARKER = "libc_start_main"
_MAIN_FALLBACK_NOTE = (
    "no main symbol and no parsable __libc_start_main pointer in the entry function"
)

# A trap ends the block, so bytes after it belong to no function even if a handler resumes there.
_TRAP_MNEMONICS = frozenset({"int3", "breakpoint", "ud2"})
_QUICK_MAIN_TRAP_HINT = (
    "function ends in {mnemonic}; if a SIGTRAP-style handler resumes past it, execution "
    "reaches code outside this function — inspect with rex_disasm_at and rex_function_define"
)

# Precompiled: _argument_address runs per call argument and should skip the re cache.
_HEX_ADDRESS_PATTERN = re.compile(r"0x[0-9a-fA-F]+")


class _DecompiledFunction(_ResolvedFunction):
    lines: list[str]
    truncated: bool


class _DecompileManyResult(TypedDict):
    functions: list[_DecompiledFunction]


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


_MainMethod = Literal["symbol", "entry-arg", "entry-fallback"]


class _QuickMainResult(TypedDict):
    entry_point: str
    method: _MainMethod
    main: str | None
    note: str | None
    hint: str | None
    function: _ResolvedFunction
    lines: list[str]
    truncated: bool


def _render_hlil_lines(hlil: HighLevelILFunction | None, max_lines: int) -> tuple[list[str], bool]:
    """Render a function's HLIL to at most ``max_lines`` truncated lines."""
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
    """Resolve a rendered HLIL argument token to an address, or None."""
    if argument is None:
        return None
    hex_match = _HEX_ADDRESS_PATTERN.search(argument)
    if hex_match is not None:
        return int(hex_match.group(0), 16)
    try:
        return call.parse_address(argument)
    except Exception:
        return None


def _entry_argument_main(
    bv: BinaryView, call: mcp.ToolCall, entry: Function
) -> tuple[_Resolution | None, str | None]:
    """Find main as the __libc_start_main-style pointer argument of the entry function."""
    hlil = entry.hlil
    if hlil is None:
        return None, f"the entry {_missing_il_message(entry, 'HLIL')}"
    for line in str(hlil).splitlines():
        if _MAIN_LIBC_MARKER not in line:
            continue
        address = _argument_address(call, _first_call_argument(line, _MAIN_LIBC_MARKER))
        if address is None:
            return None, _MAIN_FALLBACK_NOTE
        functions = bv.get_functions_containing(address)
        if functions:
            return _resolve_containing(bv, functions), None
        return (
            None,
            f"found candidate main address {address:#x} but no analyzed function contains it",
        )
    return None, _MAIN_FALLBACK_NOTE


def _tailcall_stub_target(function: Function) -> int | None:
    """The constant address a function does nothing but tail-call, else None."""
    hlil = function.hlil
    if hlil is None:
        return None
    only_statement = None
    for block in hlil.basic_blocks:
        for statement in block:
            if only_statement is not None:
                return None
            only_statement = statement
    if not isinstance(only_statement, HighLevelILTailcall):
        return None
    if not isinstance(only_statement.dest, HighLevelILConstPtr):
        return None
    return only_statement.dest.constant


def _tailcall_stub_body(bv: BinaryView, main: Function) -> Function | None:
    """Follow tail-call stubs from main to the first real body, within a bounded chain."""
    current = main
    for _ in range(_MAX_TAILCALL_HOPS + 1):
        target = _tailcall_stub_target(current)
        if target is None:
            return current if current is not main else None
        starting_here = [
            function for function in bv.get_functions_containing(target) if function.start == target
        ]
        if not starting_here:
            return None
        current = _resolve_containing(bv, starting_here).function
    return None


def _main_note(bv: BinaryView, main: Function) -> str | None:
    if main.hlil is None:
        return f"the main {_missing_il_message(main, 'HLIL')}"
    body = _tailcall_stub_body(bv, main)
    if body is None:
        return None
    return f"main is a tail-call stub; its real body is {_truncate(body.name)} at {body.start:#x}"


def _resolve_main(
    bv: BinaryView, call: mcp.ToolCall, entry: _Resolution
) -> tuple[_Resolution | None, _MainMethod, str | None]:
    """Resolve main: function symbol first, then the entry stub's pointer argument."""
    if entry.function.name in _MAIN_SYMBOL_NAMES:
        return entry, "symbol", None
    for name in _MAIN_SYMBOL_NAMES:
        candidates = sorted(bv.get_functions_by_name(name), key=lambda function: function.start)
        if candidates:
            chosen = candidates[0]
            resolved = _resolved_entry(bv, chosen, bv.get_functions_containing(chosen.start))
            return _Resolution(chosen, resolved), "symbol", None
    main, note = _entry_argument_main(bv, call, entry.function)
    if main is not None:
        return main, "entry-arg", note
    return None, "entry-fallback", note


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
    """Batch HLIL triage; a bad address rejects the whole batch (rex_disasm_many reports per item).

    :param functions: 1 to 1024 address expressions, rendered in the order given.
    :param max_lines: HLIL lines rendered per function.
    """
    bv = call.binary_view
    max_lines = _validate_range("max_lines", max_lines, 1, _MAX_DECOMPILE_LINES)
    resolved = _resolve_address_batch(call, bv, functions, _MAX_DECOMPILE_BATCH)
    rendered: list[_DecompiledFunction] = []
    for resolution in resolved:
        lines, truncated = _render_hlil_lines(resolution.function.hlil, max_lines)
        rendered.append({**resolution.entry, "lines": lines, "truncated": truncated})
    return {"functions": rendered}


@mcp.tool(read_only=True)
def rex_disasm_at(
    call: mcp.ToolCall,
    address: mcp.Address,
    before: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 4,
    after: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 8,
) -> _DisasmAtResult:
    """Address-anchored disassembly window.

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
    """Regex search over rendered HLIL text; find calls and code shapes across the view in one pass.

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


def _trap_terminator(function: Function) -> str | None:
    """The trap mnemonic when the function's last addressed instruction is a trap, else None."""
    lines = _render_function_disassembly(function)
    if not lines:
        return None
    last_address = lines[-1][0]
    # Lines at the last address include annotation continuations; only the mnemonic decides.
    last_lines = takewhile(lambda line: line[0] == last_address, reversed(lines))
    for _, text in last_lines:
        tokens = text.split()
        if tokens and tokens[0].lower() in _TRAP_MNEMONICS:
            return tokens[0].lower()
    return None


@mcp.tool(read_only=True)
def rex_quick_main(
    call: mcp.ToolCall,
    max_lines: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_DECOMPILE_LINES)] = 200,
) -> _QuickMainResult:
    """One-call fast contact: the entry point, main, and main's HLIL.

    :param max_lines: HLIL lines to render.
    """
    bv = call.binary_view
    max_lines = _validate_range("max_lines", max_lines, 1, _MAX_DECOMPILE_LINES)
    entry_point = bv.entry_point
    functions = bv.get_functions_containing(entry_point)
    if not functions:
        raise mcp.ToolError(
            "no_function", f"no analyzed function contains the entry point {entry_point:#x}"
        )
    entry = _resolve_containing(bv, functions)
    main, method, note = _resolve_main(bv, call, entry)
    if main is not None:
        note = _main_note(bv, main.function)
    resolution = main if main is not None else entry
    function = resolution.function
    lines, truncated = _render_hlil_lines(function.hlil, max_lines)
    mnemonic = _trap_terminator(function)
    hint = _QUICK_MAIN_TRAP_HINT.format(mnemonic=mnemonic) if mnemonic is not None else None
    return {
        "entry_point": hex(entry_point),
        "method": method,
        "main": hex(main.function.start) if main is not None else None,
        "note": note,
        "hint": hint,
        "function": resolution.entry,
        "lines": lines,
        "truncated": truncated,
    }
