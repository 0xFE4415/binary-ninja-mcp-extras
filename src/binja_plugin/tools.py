"""MCP tools extending Binary Ninja's built-in MCP server.

Every tool is prefixed ``rex_`` because the ``bn_`` prefix belongs to the built-in tools.
Handlers run on the MCP server thread, so none of them touch the UI thread directly.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import re
import sys
import time
from bisect import bisect_right
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path
from typing import Annotated, Any, Literal

import binaryninja
from binaryninja import Type, TypeLibrary, mcp
from binaryninja.binaryview import BinaryView
from binaryninja.enums import AnalysisState
from binaryninja.function import Function

from binja_plugin.hexpattern import HexPatternError, compile_hex_pattern

_READ_CHUNK = 4 * 1024 * 1024
_MAX_CHARS = 512
# Hard caps for list sizes and echoed strings: user-supplied size parameters are
# range-checked against these in the tool bodies — matching the schema-side
# Minimum/Maximum annotations — so out-of-range values are rejected even when handlers
# are invoked directly.
_MAX_LIMIT = 500
_MAX_HLIL_GREP_LIMIT = 200
_MAX_HLIL_GREP_FUNCTIONS = 5000
# rex_constant_find matches displayed constants, which are at most 64-bit values.
_MAX_CONSTANT_VALUE = 2**64 - 1
_MAX_CALL_PATH_DEPTH = 16
_MAX_CALL_PATHS = 50
_MAX_FUNCTION_ENTRIES = 50
_MAX_EVAL_STDOUT_CHARS = 65536
_MAX_EVAL_RESULT_CHARS = 16384
_MAX_KV_VALUE_CHARS = 65536
_MAX_KV_KEY_CHARS = 128
_MAX_TAG_DATA_CHARS = 65536
_MAX_TAG_TYPE_CHARS = 64
_MAX_STRING_READ_CHARS = 4096
# Raw pattern-string cap for rex_data_find: bounds the regex compile and the per-chunk
# read inflation (read_size grows with the pattern length) before any of that happens.
_MAX_PATTERN_CHARS = 8192
# rex_disasm_at window sizes: bounded so one call can never request an unbounded
# instruction render, whatever the containing function's size.
_MAX_DISASM_CONTEXT = 64
# rex_hlil_grep per-match context: bounded so the three-matches-per-function cap keeps
# the echoed lines per function a few dozen at most.
_MAX_HLIL_GREP_CONTEXT = 8
# rex_decompile_many caps: 16 address expressions bound one call's decompilation cost,
# and 400 lines bound the echoed text per function.
_MAX_DECOMPILE_BATCH = 16
_MAX_DECOMPILE_LINES = 400
# rex_find_functions_by_pattern example matches per function: triage wants a handful of
# hit addresses; rex_data_find already returns full match lists.
_MAX_FIND_FUNCTIONS_EXAMPLES = 5
# rex_analysis_wait: the wait runs on the MCP server thread in ~100 ms slices, so the
# hold is bounded by timeout_ms plus one slice; the in-flight cap bounds the echoed
# hotspot list (per-function analysis time doubles as an analysis profiler).
_MAX_ANALYSIS_WAIT_MS = 600000
_ANALYSIS_WAIT_SLICE_MS = 100
_MAX_ANALYSIS_INFLIGHT = 10
# rex_quick_main's resolution chain: function symbols first, then the __libc_start_main
# pointer argument of the entry stub, then an explicitly named entry-function fallback.
_MAIN_SYMBOL_NAMES = ("main", "_main")
_MAIN_LIBC_MARKER = "libc_start_main"
_MAIN_FALLBACK_NOTE = (
    "no main symbol and no parsable __libc_start_main pointer in the entry function"
)
# rex_export_* tools: sweeps write to one fixed directory and echo only a summary, so a
# large export can never flood the MCP response. The byte cap bounds each file; the
# window caps bound how much a single call selects before serialization.
_EXPORT_ROOT = Path.home() / ".binaryninja" / "exports"
_MAX_EXPORT_COMPONENT_BYTES = 255
_MAX_EXPORT_FILE_BYTES = 4 * 1024 * 1024
_MAX_EXPORT_DISASM_LINES = 400
_MAX_EXPORT_SYMBOLS = 2000
_METADATA_PREFIX = "rex/"
_TAG_ICON = "\u25c6"
_STRING_TYPES = Literal["AsciiString", "Utf16String", "Utf32String", "Utf8String"]
_EXPORT_FORMATS = Literal["csv", "json"]
# rex_undo/rex_redo echo post-operation stack depths (never the entry text) so an agent
# can stop when the depth stops changing.
# rex_annotate_many caps: 100 items bound one call's mutation cost and its echoed result
# rows; the string caps bound what reaches the core per field. The name cap is far below
# any sane symbol length, the type cap matches the pattern-string cap (both feed a
# parser), and the comment cap matches the tag-data cap.
_MAX_ANNOTATE_ITEMS = 100
_MAX_ANNOTATE_NAME_CHARS = 256
_MAX_ANNOTATE_COMMENT_CHARS = 65536
_MAX_ANNOTATE_TYPE_CHARS = 8192
_ANNOTATE_FIELDS = frozenset({"addr", "name", "comment", "prototype", "type"})
# Schema-side description of one rex_annotate_many item. The bundled mcp layer cannot
# describe object arrays structurally: mcp.Schema hands the item through as decoded JSON
# and the handler validates every field, so this schema is what the client sees while
# the checks below are what actually rejects.
_ANNOTATE_ITEMS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "addr": {
            "type": ["integer", "string"],
            "description": "address expression at or inside the function to annotate",
        },
        "name": {"type": "string", "minLength": 1, "maxLength": _MAX_ANNOTATE_NAME_CHARS},
        "comment": {"type": "string", "maxLength": _MAX_ANNOTATE_COMMENT_CHARS},
        "prototype": {"type": "string", "minLength": 1, "maxLength": _MAX_ANNOTATE_TYPE_CHARS},
        "type": {"type": "string", "minLength": 1, "maxLength": _MAX_ANNOTATE_TYPE_CHARS},
    },
    "required": ["addr"],
}
# Type-library tools: one call moves at most this many type names, and each name is
# capped before it reaches the type system — QualifiedNames have no core-side length
# bound and persist in the type database or the .bntl.
_MAX_TYPE_LIBRARY_NAMES = 64
_MAX_TYPE_NAME_CHARS = 255
_EXPORT_KINDS = Literal["types", "objects"]
# rex_struct_from_access echoes at most this many members; the struct is defined in full
# regardless, the cap bounds only the echoed list.
_MAX_STRUCT_MEMBERS = 128
# Source passed to Type.generate_auto_type_id, so the auto types this tool defines are
# identifiable in the type system as originating here.
_STRUCT_TYPE_SOURCE = "rex_struct"


def _validate_range(name: str, value: int, minimum: int, maximum: int | None = None) -> int:
    """Reject an out-of-range integer argument instead of silently normalizing it.

    The code and message follow the bundled mcp layer's own argument-error convention, and
    the schema-side ``Minimum``/``Maximum`` annotations reject the same values on the real
    server; this body-side check keeps direct handler invocation identical.
    """
    if value < minimum:
        raise mcp.ToolError(
            "invalid_params", f"Invalid integer parameter '{name}': Must be at least {minimum}"
        )
    if maximum is not None and value > maximum:
        raise mcp.ToolError(
            "invalid_params", f"Invalid integer parameter '{name}': Must be at most {maximum}"
        )
    return value


def _truncate_with_flag(value: str, limit: int = _MAX_CHARS) -> tuple[str, bool]:
    if len(value) <= limit:
        return value, False
    return value[:limit] + f"... [{len(value) - limit} chars truncated]", True


def _truncate(value: str, limit: int = _MAX_CHARS) -> str:
    return _truncate_with_flag(value, limit)[0]


def _compile_user_regex(pattern: str, ignore_case: bool = False) -> re.Pattern[str]:
    flags = re.IGNORECASE if ignore_case else 0
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise mcp.ToolError("invalid_regex", f"bad regular expression: {exc}") from None


def _name_filter(function_filter: str) -> re.Pattern[str] | None:
    if not function_filter:
        return None
    return _compile_user_regex(function_filter, ignore_case=True)


def _resolve_section(bv: BinaryView, name: str) -> tuple[int, int]:
    section = bv.get_section_by_name(name)
    if section is None:
        raise mcp.ToolError("section_not_found", f"no section named '{_truncate(name)}'")
    return section.start, section.end


def _drop[Item](items: Iterable[Item], count: int) -> Iterator[Item]:
    return islice(items, min(count, sys.maxsize), None)


def _paginate[Item](items: Iterable[Item], offset: int, limit: int) -> tuple[list[Item], int, bool]:
    """Return the ``[offset, offset + limit)`` page, the count seen, and whether more exist.

    Consumption stops one item past the window, so the count is exact only when the page is
    not truncated.
    """
    iterator = iter(items)
    # zip over range, not islice: offset is unbounded and islice rejects values above sys.maxsize.
    skipped = sum(1 for _ in zip(range(offset), iterator))
    page = list(islice(iterator, limit))
    truncated = bool(list(islice(iterator, 1)))
    return page, skipped + len(page) + int(truncated), truncated


def _text_matcher(pattern: str, regex: bool, ignore_case: bool) -> Callable[[str], bool]:
    if regex:
        compiled = _compile_user_regex(pattern, ignore_case=ignore_case)
        return lambda value: compiled.search(value) is not None
    if ignore_case:
        needle = pattern.lower()
        return lambda value: needle in value.lower()
    return lambda value: pattern in value


def _require_key(key: str) -> None:
    if not key:
        raise mcp.ToolError("invalid_key", "key must not be empty")


def _require_analyzed_function(bv: BinaryView, address: int) -> Function:
    functions = bv.get_functions_containing(address)
    if not functions:
        raise mcp.ToolError("invalid_params", f"no analyzed function contains {address:#x}")
    return functions[0]


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


def _iter_pattern_matches(
    bv: BinaryView,
    matcher: re.Pattern[bytes],
    pattern_length: int,
    bounds: tuple[int, int] | None = None,
) -> Iterator[int]:
    """Yield absolute match addresses, optionally clipped to a section range."""
    for segment in bv.segments:
        start, end = int(segment.start), segment.start + segment.length
        if bounds is not None:
            start = max(start, bounds[0])
            end = min(end, bounds[1])
        position = start
        while position < end:
            read_size = min(_READ_CHUNK + pattern_length - 1, end - position)
            chunk = bv.read(position, read_size)
            if chunk:
                for match in matcher.finditer(chunk):
                    yield position + match.start()
            position += _READ_CHUNK


def _require_function(bv: BinaryView, address: int) -> Function:
    functions = bv.get_functions_containing(address)
    if not functions:
        raise mcp.ToolError("no_function", f"no function contains {address:#x}")
    return functions[0]


def _function_entry(function: Function) -> dict[str, object]:
    return {"start": hex(function.start), "name": _truncate(function.name)}


def _render_function_disassembly(function: Any) -> list[tuple[int, str]]:
    """Render a function's addressed disassembly lines, sorted by address.

    Shared by rex_disasm_at and rex_export_disasm so both tools see exactly the same
    render. The parameter is Any-typed: the function comes back from the Any-typed
    binary view handle, and the stubbed Function type does not model basic_blocks.
    """
    lines: list[tuple[int, str]] = []
    for block in function.basic_blocks:
        for line in block.get_disassembly_text():
            # Unaddressed continuation lines cannot anchor or be reported by address.
            if line.address is not None:
                lines.append((line.address, "".join(str(token) for token in line.tokens)))
    lines.sort(key=lambda entry: entry[0])
    return lines


def _disasm_window(
    lines: list[tuple[int, str]], address: int, before: int, after: int
) -> tuple[int, int]:
    """Return the [start, end) slice of ``lines`` for the before/after window at ``address``."""
    # The anchor is the last line at or before the address: at a shared address that is
    # the labeled instruction rather than the label, and past the last instruction it is
    # the final rendered line.
    anchor = max(bisect_right(lines, address, key=lambda entry: entry[0]) - 1, 0)
    start = max(0, anchor - before)
    end = min(len(lines), anchor + 1 + after)
    return start, end


def _analysis_is_idle(bv: BinaryView) -> bool:
    """IdleState is the only state where the analysis engine has nothing queued."""
    return bv.analysis_progress.state == AnalysisState.IdleState


def _analysis_snapshot(bv: BinaryView) -> dict[str, object]:
    """Triage-style progress snapshot: engine state plus the in-flight analysis hotspots.

    Only the progress state is echoed, normalized through AnalysisState() before the name
    is taken: analysis_progress arrives already converted to the enum by the API layer,
    while analysis_info.state comes back as a raw int, so the conversion keeps the echo
    well-defined whatever shape a value arrives in. The in-flight list keeps the most
    expensive functions only, with an explicit truncated flag instead of pagination — it
    is a point-in-time snapshot, not a sweep.
    """
    progress = bv.analysis_progress
    in_flight = sorted(
        bv.analysis_info.active_info, key=lambda entry: entry.analysis_time, reverse=True
    )
    return {
        "progress": {
            "state": AnalysisState(progress.state).name,
            "count": progress.count,
            "total": progress.total,
        },
        "function_count": len(bv.functions),
        "in_flight": [
            {
                "start": hex(entry.func.start),
                "name": _truncate(entry.func.name),
                "analysis_time_ms": entry.analysis_time,
            }
            for entry in in_flight[:_MAX_ANALYSIS_INFLIGHT]
        ],
        "truncated": len(in_flight) > _MAX_ANALYSIS_INFLIGHT,
    }


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


def _validate_export_path(filename: str) -> None:
    """Reject filenames that could escape or abuse the export root.

    Pure lexical validation: no filesystem access, just the checks a plain file name must
    pass before it is joined with the export root.
    """
    if not filename:
        raise mcp.ToolError("invalid_params", "filename must not be empty")
    if filename.startswith("/"):
        raise mcp.ToolError(
            "invalid_params", "filename must be a plain file name, not an absolute path"
        )
    if "\\" in filename:
        raise mcp.ToolError("invalid_params", "filename must not contain backslashes")
    if "\x00" in filename:
        raise mcp.ToolError("invalid_params", "filename must not contain NUL bytes")
    parts = filename.split("/")
    if ".." in parts:
        raise mcp.ToolError("invalid_params", "filename must not contain '..' path components")
    for part in parts:
        if len(part.encode("utf-8")) > _MAX_EXPORT_COMPONENT_BYTES:
            # NAME_MAX applies per component, not to the joined path.
            raise mcp.ToolError(
                "invalid_params",
                f"filename component exceeds {_MAX_EXPORT_COMPONENT_BYTES} bytes",
            )


def _resolve_export_path(filename: str) -> Path:
    """Join an already-validated filename with the export root and resolve it."""
    try:
        _EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
        return (_EXPORT_ROOT / filename).resolve()
    except (OSError, ValueError) as error:
        raise mcp.ToolError("export_failed", f"could not prepare export path: {error}") from None


def _write_export_file(path: Path, text: str) -> int:
    """Write UTF-8 text to an export file, returning the encoded byte count."""
    try:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
    except (OSError, ValueError) as error:
        raise mcp.ToolError("export_failed", f"could not write export file: {error}") from None
    return len(text.encode("utf-8"))


def _fit_to_export_cap[ExportRow](
    serialize: Callable[[list[ExportRow]], str], window: list[ExportRow]
) -> tuple[str, bool]:
    """Serialize a result window, dropping trailing entries until it fits the byte cap.

    Returns the text and whether entries were dropped for size. Dropping always
    terminates at a fitting window because a window holding only its first entry is
    checked up front: when even that overflows the cap, no export is possible and the
    call is rejected instead of silently writing a near-empty file.
    """
    if window and len(serialize(window[:1]).encode("utf-8")) > _MAX_EXPORT_FILE_BYTES:
        raise mcp.ToolError("export_failed", "first entry exceeds the export byte cap")
    dropped = False
    while True:
        text = serialize(window)
        if len(text.encode("utf-8")) <= _MAX_EXPORT_FILE_BYTES:
            return text, dropped
        del window[-1]
        dropped = True


@dataclass
class _AnnotationPlan:
    """One fully validated annotation, staged for the batch transaction's apply phase."""

    function: Function
    name: str | None = None
    comment: str | None = None
    parsed_type: object | None = None


def _annotate_item_error(item: object, message: str) -> dict[str, object]:
    """Result row for an item too broken to carry an address: echo the whole item."""
    return {"addr": _truncate(repr(item)), "ok": False, "error": message}


def _annotate_addr_error(addr_value: object, message: str) -> dict[str, object]:
    """Result row for an item whose address itself failed a check: echo the address."""
    return {"addr": _truncate(str(addr_value)), "ok": False, "error": message}


def _annotate_function_error(address: int, message: str) -> dict[str, object]:
    """Result row for an item that parsed to a known address but failed there."""
    return {"addr": hex(address), "ok": False, "error": message}


def _annotate_resolve(
    call: mcp.ToolCall, bv: BinaryView, item: Any
) -> tuple[dict[str, object], _AnnotationPlan | None]:
    """Validate one annotation item completely, staging a plan only if it can fully apply.

    The type string is parsed up front and discarded until the apply phase, so an item
    can never half-apply: everything that can fail on the item's own content fails here,
    before any mutation is staged.
    """
    if not isinstance(item, dict):
        return _annotate_item_error(item, "each item must be a JSON object"), None
    if "addr" not in item:
        return _annotate_item_error(item, "addr is required"), None
    addr_value = item["addr"]
    if not isinstance(addr_value, (int, str)) or isinstance(addr_value, bool):
        # bool is an int subclass: a JSON true/false address is a caller bug.
        return (
            _annotate_addr_error(
                addr_value, "addr must be an integer or a string address expression"
            ),
            None,
        )
    unknown = sorted(str(key) for key in item if key not in _ANNOTATE_FIELDS)
    if unknown:
        return _annotate_addr_error(addr_value, f"unknown field(s): {', '.join(unknown)}"), None
    try:
        address = call.parse_address(addr_value)
    except Exception as error:
        return _annotate_addr_error(addr_value, f"bad address expression: {error}"), None
    functions = bv.get_functions_containing(address)
    if not functions:
        return (
            _annotate_function_error(address, f"no analyzed function contains {address:#x}"),
            None,
        )
    function = functions[0]
    name = item.get("name")
    comment = item.get("comment")
    if name is not None and (not isinstance(name, str) or not name):
        return _annotate_function_error(address, "name must be a non-empty string"), None
    if name is not None and len(name) > _MAX_ANNOTATE_NAME_CHARS:
        return (
            _annotate_function_error(
                address, f"name exceeds {_MAX_ANNOTATE_NAME_CHARS} characters"
            ),
            None,
        )
    if comment is not None and not isinstance(comment, str):
        return _annotate_function_error(address, "comment must be a string"), None
    if comment is not None and len(comment) > _MAX_ANNOTATE_COMMENT_CHARS:
        return (
            _annotate_function_error(
                address, f"comment exceeds {_MAX_ANNOTATE_COMMENT_CHARS} characters"
            ),
            None,
        )
    prototype = item.get("prototype")
    type_text = item.get("type")
    for field_name, value in (("prototype", prototype), ("type", type_text)):
        if value is not None and (not isinstance(value, str) or not value):
            return (
                _annotate_function_error(address, f"{field_name} must be a non-empty string"),
                None,
            )
        if value is not None and len(value) > _MAX_ANNOTATE_TYPE_CHARS:
            return (
                _annotate_function_error(
                    address, f"{field_name} exceeds {_MAX_ANNOTATE_TYPE_CHARS} characters"
                ),
                None,
            )
    if prototype is not None and type_text is not None and prototype != type_text:
        return (
            _annotate_function_error(
                address,
                "prototype and type are the same operation; give identical strings or only one",
            ),
            None,
        )
    type_string = prototype if prototype is not None else type_text
    parsed_type: object | None = None
    if type_string is not None:
        try:
            parsed_type, _ = bv.parse_type_string(type_string)
        except Exception as error:
            return _annotate_function_error(address, f"bad type: {_truncate(str(error))}"), None
    return (
        {"addr": hex(function.start), "ok": True},
        _AnnotationPlan(function=function, name=name, comment=comment, parsed_type=parsed_type),
    )


def _validate_type_names(names: list[str]) -> list[str]:
    """Range-check a caller-supplied list of type names, rejecting instead of normalizing.

    Shared by the import and export type-library tools; the list cap bounds one call's
    type-system work (each import can recursively pull in dependency libraries), and the
    per-name cap covers names that end up persisted in the type database or the .bntl.
    """
    if not isinstance(names, list):
        raise mcp.ToolError("invalid_params", "names must be a list of type names")
    if not 1 <= len(names) <= _MAX_TYPE_LIBRARY_NAMES:
        raise mcp.ToolError(
            "invalid_params",
            f"names must contain between 1 and {_MAX_TYPE_LIBRARY_NAMES} entries",
        )
    for index, name in enumerate(names):
        if not isinstance(name, str):
            raise mcp.ToolError("invalid_params", f"names[{index}] must be a string type name")
        if not name:
            raise mcp.ToolError("invalid_params", f"names[{index}] must not be empty")
        if len(name) > _MAX_TYPE_NAME_CHARS:
            raise mcp.ToolError(
                "invalid_params",
                f"names[{index}] exceeds {_MAX_TYPE_NAME_CHARS} characters",
            )
    return names


@mcp.tool(read_only=True)
def rex_analysis_wait(
    call: mcp.ToolCall,
    timeout_ms: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_ANALYSIS_WAIT_MS)],
) -> dict[str, object]:
    """Bounded wait for background analysis with a progress snapshot at expiry.

    Fires nothing itself: pair it with the async bn_analysis_update. This tool then
    sleeps in ~100 ms slices until the analysis engine goes idle or the deadline
    passes, so the server hold is bounded by timeout_ms plus one slice either way —
    never the whole-analysis hold of bn_analysis_update_and_wait. timeout_ms=0 is a
    pure snapshot. The response mirrors what bn_binary_triage exposes about analysis:
    the engine state with its count/total, the function count, and the in-flight
    functions with their per-function analysis time (the hotspot profiler), capped at
    the 10 most expensive entries with a ``truncated`` flag.

    :param timeout_ms: Maximum time to wait in milliseconds (0 to 600000); 0 snapshots
        the current state without waiting.
    """
    bv = call.binary_view
    timeout_ms = _validate_range("timeout_ms", timeout_ms, 0, _MAX_ANALYSIS_WAIT_MS)
    started = time.monotonic()
    deadline = started + timeout_ms / 1000
    completed = _analysis_is_idle(bv)
    while not completed and time.monotonic() < deadline:
        time.sleep(_ANALYSIS_WAIT_SLICE_MS / 1000)
        completed = _analysis_is_idle(bv)
    elapsed_ms = round((time.monotonic() - started) * 1000)
    return {"completed": completed, "elapsed_ms": elapsed_ms, **_analysis_snapshot(bv)}


@mcp.tool(destructive=True)
def rex_annotate_many(
    call: mcp.ToolCall,
    items: list[Annotated[Any, mcp.Schema(_ANNOTATE_ITEMS_SCHEMA)]],
) -> dict[str, object]:
    """Apply many function annotations in one undoable transaction.

    Batch counterpart of one-at-a-time renaming and commenting: up to 100 items of
    ``{addr, name?, comment?, prototype?, type?}`` in one call. Every item resolves
    before anything is applied; the applying items commit inside a single
    ``bv.undoable_transaction()`` (begin actions, commit on success, revert and re-raise
    on failure), so the whole batch is one undo step that ``rex_undo`` reverses as a
    unit. If a core error escapes mid-apply, the context manager has already reverted
    every change and the response says the batch rolled back.

    Per-item failures never abort the batch: an address with no analyzed function, an
    unparsable address, or an invalid field is one ``{"ok": false}`` row while the other
    items still apply. When every item fails, nothing is applied and no undo step is
    created. Each row echoes the annotated function's start on success (the input may
    have been mid-function or a symbol name) or what was looked up on failure.

    ``prototype`` and ``type`` are aliases, not two paths: Binary Ninja stores one user
    type per function and both go through ``Function.set_user_type``. The string is
    parsed per item with the parsed name discarded — unlike the ``type`` property setter,
    which would also rename the function. Give identical strings, or only one.

    Per item the apply order is ``comment``, then the type, then ``name`` last, so an
    explicit ``name`` has the final word on naming.

    :param items: 1 to 100 objects of ``{addr, name?, comment?, prototype?, type?}``;
        ``addr`` is an address expression (integer or string), the rest are strings.
    """
    bv = call.binary_view
    if not isinstance(items, list):
        raise mcp.ToolError("invalid_params", "items must be a list of annotation objects")
    if not 1 <= len(items) <= _MAX_ANNOTATE_ITEMS:
        raise mcp.ToolError(
            "invalid_params", f"items must contain between 1 and {_MAX_ANNOTATE_ITEMS} entries"
        )
    results: list[dict[str, object]] = []
    staged: list[_AnnotationPlan] = []
    for item in items:
        row, plan = _annotate_resolve(call, bv, item)
        results.append(row)
        if plan is not None:
            staged.append(plan)
    if staged:
        try:
            with bv.undoable_transaction():
                for plan in staged:
                    if plan.comment is not None:
                        plan.function.comment = plan.comment
                    if plan.parsed_type is not None:
                        plan.function.set_user_type(plan.parsed_type)
                    if plan.name is not None:
                        plan.function.name = plan.name
        except Exception as error:
            # undoable_transaction reverted the whole batch core-side before this runs;
            # saying so keeps a caller from retrying a half-applied batch.
            raise mcp.ToolError("annotate_failed", f"batch rolled back: {error}") from None
    applied = sum(1 for row in results if row["ok"] is True)
    return {"applied": applied, "failed": len(results) - applied, "results": results}


@mcp.tool(destructive=True)
def rex_binary_close(call: mcp.ToolCall) -> dict[str, object]:
    """Discard this view's unsaved changes and close it.

    The stock bn_binary_close refuses a modified view with ``requires_user_choice``,
    so agent-created views survive the agent. This tool closes programmatically: it
    clears the file's modified flag (``FileMetadata.modified = False``, the
    BNMarkFileSaved path — nothing is written to disk) and then closes the file
    through the core (``FileMetadata.close``, verified live on a scratch copy of
    /bin/true). Destructive: unpatched bytes, tags, and unsaved analysis state are
    lost; save first if any of it is worth keeping.
    """
    file_metadata = call.binary_view.file
    # The UI adapter keys its discard refusal on this flag; clearing it is the
    # programmatic equivalent of choosing "Discard" in the close prompt.
    file_metadata.modified = False
    try:
        file_metadata.close()
    except Exception as error:
        raise mcp.ToolError("close_failed", f"could not close the view: {error}") from None
    return {"closed": True, "path": _truncate(file_metadata.filename)}


@mcp.tool(read_only=True)
def rex_call_paths(
    call: mcp.ToolCall,
    from_addr: mcp.Address,
    to_addr: mcp.Address,
    direction: Literal["callers", "callees"] = "callers",
    max_depth: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_CALL_PATH_DEPTH)] = 8,
    max_paths: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_CALL_PATHS)] = 5,
) -> dict[str, object]:
    """Bounded breadth-first search for call paths between two functions.

    :param from_addr: Address inside the starting function.
    :param to_addr: Address inside the target function.
    :param direction: Walk "callers" edges (what reaches the target) or "callees" edges.
    :param max_depth: Maximum number of edges to walk from the starting function (1 to 16).
    :param max_paths: Maximum number of paths to return (1 to 50).
    """
    bv = call.binary_view
    max_depth = _validate_range("max_depth", max_depth, 1, _MAX_CALL_PATH_DEPTH)
    max_paths = _validate_range("max_paths", max_paths, 1, _MAX_CALL_PATHS)
    source = _require_function(bv, from_addr)
    target = _require_function(bv, to_addr)
    paths: list[list[dict[str, object]]] = []
    if source.start == target.start:
        return {
            "reachable": True,
            "paths": [[_function_entry(source)]],
            "truncated": False,
            "explored": 1,
        }
    queue: deque[tuple[Function, list[Function]]] = deque([(source, [source])])
    visited = {source.start}
    explored = 0
    hit_path_cap = False
    while queue and len(paths) < max_paths:
        function, path = queue.popleft()
        if len(path) > max_depth:
            continue
        explored += 1
        edges = function.callers if direction == "callers" else function.callees
        for neighbor in sorted(edges, key=lambda item: item.start):
            if neighbor.start == target.start:
                paths.append([_function_entry(item) for item in [*path, neighbor]])
                if len(paths) >= max_paths:
                    # One function's call sites can list the target several times; stop
                    # appending so the result never exceeds max_paths.
                    hit_path_cap = True
                    break
            elif neighbor.start not in visited:
                visited.add(neighbor.start)
                queue.append((neighbor, [*path, neighbor]))
    # hit_path_cap is the only truncation signal: paths can never exceed max_paths (the inner
    # loop breaks first), and reaching max_paths only happens through that same append.
    return {
        "reachable": bool(paths),
        "paths": paths,
        "truncated": hit_path_cap,
        "explored": explored,
    }


@mcp.tool(read_only=True)
def rex_constant_find(
    call: mcp.ToolCall,
    value: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_CONSTANT_VALUE)],
    function_filter: str = "",
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """Find functions whose rendered instructions reference an immediate constant value.

    Uses the core's linear-view constant search (the engine behind Search > For
    Constant), so the core renders each function's instruction text once instead of
    this tool generating IL for every function. A constant counts as referenced when
    an instruction line of the function displays it as a constant or pointer token;
    lines outside any function are ignored. The scan stops as soon as the requested
    result window is known to be complete, and a full view sweep — the worst case,
    reached only when ``value`` never appears — stays a bounded, core-side pass.
    Each function reports at most the first 6 matching addresses.

    :param value: Immediate value to search for, e.g. 31337 or 65534; compared
        against displayed (unsigned) constants, so 0 to 2**64 - 1.
    :param function_filter: Case-insensitive regular expression matched against function names.
    :param limit: Maximum number of matching functions to return (0 to 500).
    :param offset: Number of matching functions to skip before collecting results (>= 0).
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
    :param limit: Maximum number of matches to return (0 to 500).
    :param offset: Number of matches to skip before collecting results (>= 0).
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
        hlil = function.hlil
        source_lines = str(hlil).splitlines() if hlil is not None else []
        rendered.append(
            {
                **_function_entry(function),
                "lines": [_truncate(line) for line in source_lines[:max_lines]],
                "truncated": len(source_lines) > max_lines,
            }
        )
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
    before = _validate_range("before", before, 0, _MAX_DISASM_CONTEXT)
    after = _validate_range("after", after, 0, _MAX_DISASM_CONTEXT)
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


@mcp.tool(destructive=True)
def rex_eval_python(call: mcp.ToolCall, code: str) -> dict[str, object]:
    """Run trusted Python against the Binary Ninja API with the active view exposed as bv.

    This is the escape hatch for everything the other tools do not cover. It runs arbitrary
    code with full access to the Binary Ninja API, so it is marked destructive.

    :param code: Python source to execute; assign to ``result`` to return a value.
    """
    namespace: dict[str, object] = {
        "bv": call.binary_view,
        "call": call,
        "binaryninja": binaryninja,
        "bn": binaryninja,
    }
    buffer = io.StringIO()
    raw_result: str | None = None
    error_message: str | None = None
    try:
        with contextlib.redirect_stdout(buffer):
            exec(code, namespace)
        if "result" in namespace:
            # repr() inside the try: a raising __repr__ must take the error path below, not
            # escape the handler and drop the captured stdout.
            raw_result = repr(namespace["result"])
    except Exception as error:
        # Keep failures out of the mcp layer's uncapped str(error) ToolError path.
        error_message = str(error)

    stdout, stdout_truncated = _truncate_with_flag(buffer.getvalue(), _MAX_EVAL_STDOUT_CHARS)
    if error_message is not None:
        message, error_truncated = _truncate_with_flag(error_message)
        return {
            "stdout": stdout,
            "stdout_truncated": stdout_truncated,
            "result": None,
            "result_truncated": False,
            "error": message,
            "error_truncated": error_truncated,
        }
    result, result_truncated = (
        _truncate_with_flag(raw_result, _MAX_EVAL_RESULT_CHARS)
        if raw_result is not None
        else (None, False)
    )
    return {
        "stdout": stdout,
        "stdout_truncated": stdout_truncated,
        "result": result,
        "result_truncated": result_truncated,
        "error": None,
        "error_truncated": False,
    }


@mcp.tool()
def rex_export_disasm(
    call: mcp.ToolCall,
    address: mcp.Address,
    before: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 4,
    after: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 8,
    max_lines: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_EXPORT_DISASM_LINES)] = 200,
    filename: str = "",
) -> dict[str, object]:
    """Export one analyzed function's disassembly window to a file.

    Anti-flood export: the rendered lines are written to disk and the response echoes
    only ``path``, ``bytes_written``, ``lines`` and ``truncated`` — never the
    disassembly text itself, so a large sweep cannot flood the MCP response. Address
    handling matches rex_disasm_at exactly: the window is anchored at the instruction
    containing ``address``, clipped at the containing function's edges, and an address
    outside every analyzed function is rejected rather than snapped to the nearest one.

    Accepted cost: the render materializes the whole function's disassembly lines in
    memory before the ``max_lines`` cap and the export byte cap apply — the same cost
    class as the existing echo tools. Each file line is the rendered instruction text
    (the ``text`` field rex_disasm_at echoes), one instruction per line, LF endings.
    ``truncated`` is true unless the file holds every rendered addressed line of the
    containing function: lines were left out by the before/after window, ``max_lines``,
    or the byte cap.

    :param address: Address expression inside the target function; accepts hex like
        0x401000, symbols, and Binary Ninja expressions.
    :param before: Instructions to include before the anchor (0 to 64).
    :param after: Instructions to include after the anchor (0 to 64).
    :param max_lines: Maximum number of lines to export (1 to 400).
    :param filename: Plain file name inside the export root; overwritten if it exists.
    """
    bv = call.binary_view
    before = _validate_range("before", before, 0, _MAX_DISASM_CONTEXT)
    after = _validate_range("after", after, 0, _MAX_DISASM_CONTEXT)
    max_lines = _validate_range("max_lines", max_lines, 1, _MAX_EXPORT_DISASM_LINES)
    _validate_export_path(filename)
    lines = _render_function_disassembly(_require_analyzed_function(bv, address))
    start, end = _disasm_window(lines, address, before, after)
    window = lines[start:end][:max_lines]

    def serialize(selected: list[tuple[int, str]]) -> str:
        return "".join(f"{text}\n" for _, text in selected)

    text, dropped = _fit_to_export_cap(serialize, window)
    resolved = _resolve_export_path(filename)
    return {
        "path": str(resolved),
        "bytes_written": _write_export_file(resolved, text),
        "lines": len(window),
        "truncated": len(window) < len(lines) or dropped,
    }


@mcp.tool()
def rex_export_symbols(
    call: mcp.ToolCall,
    start: Annotated[int, mcp.Minimum(0)],
    end: int,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_EXPORT_SYMBOLS)] = 500,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
    format: _EXPORT_FORMATS = "csv",
    filename: str = "",
) -> dict[str, object]:
    """Export the symbols in an address range to a file.

    Anti-flood export: symbols are written to disk and the response echoes only
    ``path``, ``bytes_written``, ``rows``, ``total`` and ``truncated`` — never the
    symbol table itself. Symbols come from the core's range query
    (``bv.get_symbols(start, length)``), are sorted by address ascending, and ``total``
    is the exact count in ``[start, end)``; the window is ``offset`` to
    ``offset + limit`` of that sorted list.

    The sort-then-slice here is a deliberate divergence from the early-stop pagination
    of the string search tools: an export file must contain the true window of the
    sorted listing, not an unsorted first-fit subset, and the range query already bounds
    the enumeration cost.

    CSV rows are ``symbol_address,symbol_type,name`` with commas in names quoted by the
    csv module; JSON is an indented array of the window's rows. Both are written UTF-8
    with LF endings. ``truncated`` is true when the window was clipped by
    ``offset``/``limit`` or when rows were dropped from its end to fit the export byte
    cap.

    :param start: Start of the address range (inclusive, >= 0).
    :param end: End of the address range (exclusive); must be greater than ``start``.
    :param limit: Maximum number of symbols to export (0 to 2000).
    :param offset: Number of sorted symbols to skip before the window starts (>= 0).
    :param format: Output format, "csv" or "json".
    :param filename: Plain file name inside the export root; overwritten if it exists.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_EXPORT_SYMBOLS)
    offset = _validate_range("offset", offset, 0)
    start = _validate_range("start", start, 0)
    if start >= end:
        raise mcp.ToolError("invalid_params", "end must be greater than start")
    _validate_export_path(filename)
    # The schema-side Literal and the body-side check below must agree; widening to str
    # keeps the body check statically reachable for direct handler invocation.
    requested: str = format
    if requested not in ("csv", "json"):
        raise mcp.ToolError("invalid_params", f"format must be 'csv' or 'json', not '{requested}'")
    symbols = bv.get_symbols(start, end - start)
    # Core symbol order is not guaranteed sorted; sort before slicing so the file holds
    # a true window of the address-ordered listing (see the docstring above).
    ordered = sorted(symbols, key=lambda symbol: symbol.address)
    total = len(ordered)
    window = [
        (symbol.address, symbol.type.name, symbol.name)
        for symbol in ordered[offset : offset + limit]
    ]

    def serialize(rows: list[tuple[int, str, str]]) -> str:
        if requested == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer, lineterminator="\n")
            writer.writerow(["symbol_address", "symbol_type", "name"])
            for address, symbol_type, name in rows:
                writer.writerow([hex(address), symbol_type, name])
            return buffer.getvalue()
        return json.dumps(
            [
                {"symbol_address": hex(address), "symbol_type": symbol_type, "name": name}
                for address, symbol_type, name in rows
            ],
            indent=2,
        )

    text, dropped = _fit_to_export_cap(serialize, window)
    resolved = _resolve_export_path(filename)
    return {
        "path": str(resolved),
        "bytes_written": _write_export_file(resolved, text),
        "rows": len(window),
        "truncated": offset + limit < total or dropped,
        "total": total,
    }


@mcp.tool(read_only=True)
def rex_find_functions_by_pattern(
    call: mcp.ToolCall,
    pattern: str,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """Which functions contain a byte pattern.

    Scans mapped memory rex_data_find-style (chunked reads overlapping by
    pattern_length - 1, so straddling matches are found exactly once) and maps every
    match to the analyzed function containing it. Matches in data or in gaps between
    functions are ignored. Functions are reported in first-match order with a true
    match count and up to 5 example addresses; an empty result is a valid empty list,
    not an error. Like rex_data_find, the scan stops at the first function past the
    requested window, so when ``truncated`` is true the counts near the end of the
    result can be incomplete.

    :param pattern: Hex byte pattern, e.g. "48 8b ?? 05"; "??" matches any single byte.
    :param limit: Maximum number of matching functions to return (0 to 500).
    :param offset: Number of matching functions to skip before collecting results (>= 0).
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    matcher, pattern_length = _compile_pattern(pattern)
    hits: dict[int, _FunctionHits] = {}
    truncated = False
    for address in _iter_pattern_matches(bv, matcher, pattern_length):
        containing = bv.get_functions_containing(address)
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


@mcp.tool(read_only=True)
def rex_function_containing(call: mcp.ToolCall, addr: mcp.Address) -> dict[str, object]:
    """List the functions that contain an address.

    :param addr: Address to look up.
    """
    functions = call.binary_view.get_functions_containing(addr)
    if not functions:
        raise mcp.ToolError("no_function", f"no function contains {addr:#x}")
    return {
        "functions": [_function_entry(function) for function in functions[:_MAX_FUNCTION_ENTRIES]],
        "truncated": len(functions) > _MAX_FUNCTION_ENTRIES,
    }


@mcp.tool()
def rex_function_define(call: mcp.ToolCall, start: mcp.Address) -> dict[str, object]:
    """Turn the bytes at an address into a function.

    :param start: Address of the new function's entry point.
    """
    function = call.binary_view.create_user_function(start)
    if function is None:
        raise mcp.ToolError("define_failed", f"could not create a function at {start:#x}")
    return _function_entry(function)


@mcp.tool(destructive=True)
def rex_function_undefine(call: mcp.ToolCall, start: mcp.Address) -> dict[str, object]:
    """Remove the user function covering an address.

    :param start: Any address inside the function to remove.
    """
    function = _require_function(call.binary_view, start)
    call.binary_view.remove_user_function(function)
    return _function_entry(function)


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


@mcp.tool(destructive=True)
def rex_kv_delete(call: mcp.ToolCall, key: str) -> dict[str, object]:
    """Delete a value previously stored with rex_kv_set.

    :param key: Key to delete.
    """
    _require_key(key)
    call.binary_view.remove_metadata(_METADATA_PREFIX + key)
    return {"key": _truncate(key)}


@mcp.tool(read_only=True)
def rex_kv_get(call: mcp.ToolCall, key: str) -> dict[str, object]:
    """Read a string previously stored with rex_kv_set.

    :param key: Key to read.
    """
    _require_key(key)
    try:
        value = call.binary_view.query_metadata(_METADATA_PREFIX + key)
    except Exception:
        raise mcp.ToolError("not_found", f"no value stored under '{_truncate(key)}'") from None
    text, truncated = _truncate_with_flag(str(value), _MAX_KV_VALUE_CHARS)
    return {"key": _truncate(key), "value": text, "truncated": truncated}


@mcp.tool()
def rex_kv_set(call: mcp.ToolCall, key: str, value: str) -> dict[str, object]:
    """Store a string in the binary view database as persistent scratch data.

    Values are stored under the "rex/" metadata namespace and survive across sessions.

    :param key: Key to store under.
    :param value: String value to store.
    """
    _require_key(key)
    if len(key) > _MAX_KV_KEY_CHARS:
        # The key becomes part of the persistent metadata path with no core-side length bound.
        raise mcp.ToolError("key_too_large", f"key exceeds {_MAX_KV_KEY_CHARS} characters")
    if len(value) > _MAX_KV_VALUE_CHARS:
        raise mcp.ToolError("value_too_large", f"value exceeds {_MAX_KV_VALUE_CHARS} characters")
    call.binary_view.store_metadata(_METADATA_PREFIX + key, value)
    preview, truncated = _truncate_with_flag(value)
    return {"key": _truncate(key), "length": len(value), "value": preview, "truncated": truncated}


@mcp.tool(destructive=True)
def rex_memory_write(call: mcp.ToolCall, addr: mcp.Address, hex_data: str) -> dict[str, object]:
    """Overwrite bytes in the binary view with a hex byte string.

    :param addr: Address to write to.
    :param hex_data: Hex byte string to write, e.g. "90 90" or "9090".
    """
    compact = "".join(hex_data.split())
    if not compact:
        raise mcp.ToolError("invalid_hex", "hex_data is empty")
    try:
        data = bytes.fromhex(compact)
    except ValueError:
        raise mcp.ToolError("invalid_hex", "hex_data must contain hex byte pairs") from None
    written = call.binary_view.write(addr, data)
    return {"address": hex(addr), "bytes_written": written}


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
    hlil = function.hlil
    source_lines = str(hlil).splitlines() if hlil is not None else []
    return {
        "entry_point": hex(entry_point),
        "method": method,
        "main": hex(main.start) if main is not None else None,
        "note": note,
        "function": _function_entry(function),
        "lines": [_truncate(line) for line in source_lines[:max_lines]],
        "truncated": len(source_lines) > max_lines,
    }


@mcp.tool(destructive=True)
def rex_redo(call: mcp.ToolCall) -> dict[str, object]:
    """Redo the last undone transaction in the view's undo database.

    The counterpart of rex_undo: re-applies the entry rex_undo most recently took off
    the undo stack. The stack is shared with the GUI user, so this may redo their last
    undone edit too. An empty stack is a core-side no-op, not an error; the
    post-operation depths report the state the caller lands in.
    """
    try:
        call.binary_view.redo()
    except Exception as error:
        raise mcp.ToolError("redo_failed", f"could not redo: {error}") from None
    return {
        "redone": True,
        "undo_left": len(call.binary_view.file.undo_entries),
        "redo_left": len(call.binary_view.file.redo_entries),
    }


@mcp.tool(read_only=True)
def rex_string_read_at(
    call: mcp.ToolCall,
    addr: mcp.Address,
    max_chars: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_STRING_READ_CHARS)] = _MAX_CHARS,
) -> dict[str, object]:
    """Read the detected string at an address.

    :param addr: Address of the string.
    :param max_chars: Truncate long string values to this many characters (1 to 4096).
    """
    max_chars = _validate_range("max_chars", max_chars, 1, _MAX_STRING_READ_CHARS)
    string = call.binary_view.get_string_at(addr)
    if string is None:
        raise mcp.ToolError("no_string", f"no detected string at {addr:#x}")
    value, truncated = _truncate_with_flag(string.value, max_chars)
    return {
        "address": hex(string.start),
        "length": len(string),
        "type": string.type.name,
        "value": value,
        "truncated": truncated,
    }


@mcp.tool(read_only=True)
def rex_string_search(
    call: mcp.ToolCall,
    pattern: str = "",
    regex: bool = False,
    ignore_case: bool = False,
    section: str | None = None,
    string_type: _STRING_TYPES | None = None,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """Search the binary's detected strings by substring or regular expression.

    Regular expressions run on Python's ``re`` with no timeout, so a pattern with
    catastrophic backtracking can stall the search; prefer substring mode for untrusted input.

    :param pattern: Substring or regular expression to match; empty matches every string.
    :param regex: Treat pattern as a regular expression instead of a substring.
    :param ignore_case: Match case-insensitively.
    :param section: Only include strings within this section.
    :param string_type: Only include strings of this type.
    :param limit: Maximum number of strings to return (0 to 500).
    :param offset: Number of matching strings to skip before collecting results (>= 0).
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    matches_text = _text_matcher(pattern, regex, ignore_case)
    bounds = _resolve_section(bv, section) if section is not None else None

    def keep(string: Any) -> bool:
        if string_type is not None and string.type.name != string_type:
            return False
        if bounds is not None and not bounds[0] <= string.start < bounds[1]:
            return False
        return matches_text(string.value)

    page, total, truncated = _paginate(filter(keep, bv.strings), offset, limit)
    found = [
        {
            "address": hex(string.start),
            "length": len(string),
            "type": string.type.name,
            "value": _truncate(string.value),
        }
        for string in page
    ]
    return {"total": total, "truncated": truncated, "strings": found}


@mcp.tool()
def rex_struct_from_access(call: mcp.ToolCall, name: str) -> dict[str, object]:
    """Infer and define a struct from the view's recorded offset accesses.

    Runs the same core call behind Binary Ninja's "Create Structure" action
    (``bv.create_structure_from_offset_access``): the core infers the members from the
    offset accesses recorded in the view, no C source is authored. The resulting struct
    is then defined in the view under an auto type id derived from this tool's source
    marker and ``name`` (``Type.generate_auto_type_id``), so a repeated call with the
    same name replaces the earlier auto type; user types are never overwritten (the core
    deconflicts the registered name, echoed back as ``registered``).

    When the core has no usable accesses for ``name`` it refuses to build a structure
    and the call fails with ``create_failed`` — an empty struct is only echoed if the
    core actually hands one back. At most 128 members are echoed, with ``member_count``
    and ``truncated`` covering the rest.

    :param name: Name for the new structure (1 to 255 characters).
    """
    bv = call.binary_view
    if not name:
        raise mcp.ToolError("invalid_params", "name must not be empty")
    if len(name) > _MAX_TYPE_NAME_CHARS:
        raise mcp.ToolError("invalid_params", f"name exceeds {_MAX_TYPE_NAME_CHARS} characters")
    try:
        structure = bv.create_structure_from_offset_access(name)
    except Exception as error:
        raise mcp.ToolError(
            "create_failed", f"could not create a structure from offset accesses: {error}"
        ) from None
    members = structure.members
    registered = bv.define_type(
        Type.generate_auto_type_id(_STRUCT_TYPE_SOURCE, name), name, structure
    )
    return {
        "name": _truncate(name),
        "registered": _truncate(str(registered)),
        "width": structure.width,
        "member_count": len(members),
        "members": [
            {
                "offset": member.offset,
                "name": _truncate(member.name),
                "type": _truncate(str(member.type)),
            }
            for member in members[:_MAX_STRUCT_MEMBERS]
        ],
        "truncated": len(members) > _MAX_STRUCT_MEMBERS,
    }


@mcp.tool(read_only=True)
def rex_tag_list(
    call: mcp.ToolCall, limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100
) -> dict[str, object]:
    """List the tags set on the binary view.

    :param limit: Maximum number of tags to return (0 to 500).
    """
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    tags = []
    for address, tag in call.binary_view.get_tags():
        data, data_truncated = _truncate_with_flag(tag.data)
        tags.append(
            {
                "address": hex(address),
                "tag_type": tag.type.name,
                "data": data,
                "data_truncated": data_truncated,
            }
        )
    return {"total": len(tags), "truncated": len(tags) > limit, "tags": tags[:limit]}


@mcp.tool()
def rex_tag_set(
    call: mcp.ToolCall, addr: mcp.Address, tag_type: str, data: str, create_missing: bool = True
) -> dict[str, object]:
    """Attach a Binary Ninja tag at an address, visible in the GUI.

    :param addr: Address to tag; accepts expressions like "main" or ".text + 0x10".
    :param tag_type: Tag type name, e.g. "Crashes" or "Finding".
    :param data: Tag text.
    :param create_missing: Create tag_type when it does not exist yet.
    """
    bv = call.binary_view
    if len(data) > _MAX_TAG_DATA_CHARS:
        raise mcp.ToolError("data_too_large", f"tag data exceeds {_MAX_TAG_DATA_CHARS} characters")
    if tag_type not in bv.tag_types:
        if not create_missing:
            raise mcp.ToolError("tag_type_not_found", f"no tag type named '{_truncate(tag_type)}'")
        if len(tag_type) > _MAX_TAG_TYPE_CHARS:
            # create_tag_type persists the name in the database with no core-side length bound.
            raise mcp.ToolError(
                "tag_type_too_large", f"tag type name exceeds {_MAX_TAG_TYPE_CHARS} characters"
            )
        bv.create_tag_type(tag_type, _TAG_ICON)
    bv.add_tag(addr, tag_type, data)
    data_preview, data_truncated = _truncate_with_flag(data)
    return {
        "address": hex(addr),
        "tag_type": _truncate(tag_type),
        "data": data_preview,
        "data_truncated": data_truncated,
        "length": len(data),
    }


@mcp.tool()
def rex_type_library_export(
    call: mcp.ToolCall,
    library_name: str,
    names: list[str],
    kind: _EXPORT_KINDS = "types",
    filename: str = "",
) -> dict[str, object]:
    """Export recovered types or objects into a new .bntl in the export root.

    Creates an empty type library named ``library_name`` bound to this view's
    architecture, resolves each requested name in the view and recursively exports it as
    a plain type (``kind="types"``) or as a named object such as a function signature
    (``kind="objects"``). Referenced types are copied in or recorded as dependencies by
    the core. Names not present in the view are reported per-name under ``failed``; the
    rest still export. The library is finalized and written through the same export-root
    discipline as rex_export_disasm: validated plain filename, fixed root, and the same
    byte cap — the core serializes the .bntl itself, so the size is only known after the
    write, and an over-cap file is removed rather than left behind.

    :param library_name: Name for the new type library (1 to 255 characters).
    :param names: Type names to export from the view; 1 to 64 entries.
    :param kind: Export entries as "types" (type definitions) or "objects"
        (named functions/variables).
    :param filename: Plain file name inside the export root; overwritten if it exists.
    """
    bv = call.binary_view
    if not library_name:
        raise mcp.ToolError("invalid_params", "library_name must not be empty")
    if len(library_name) > _MAX_TYPE_NAME_CHARS:
        raise mcp.ToolError(
            "invalid_params", f"library_name exceeds {_MAX_TYPE_NAME_CHARS} characters"
        )
    _validate_type_names(names)
    _validate_export_path(filename)
    # The schema-side Literal and the body-side check below must agree; widening to str
    # keeps the body check statically reachable for direct handler invocation.
    requested: str = kind
    if requested not in ("types", "objects"):
        raise mcp.ToolError(
            "invalid_params", f"kind must be 'types' or 'objects', not '{requested}'"
        )
    arch = bv.arch
    if arch is None:
        raise mcp.ToolError(
            "no_arch", "the binary view has no architecture to create a type library for"
        )
    library = TypeLibrary.new(arch, library_name)
    exported: list[str] = []
    failed: list[dict[str, str]] = []
    for name in names:
        type_obj = bv.get_type_by_name(name)
        if type_obj is None:
            failed.append({"requested": name, "reason": "no type with this name in the view"})
            continue
        if requested == "types":
            bv.export_type_to_library(library, name, type_obj)
        else:
            bv.export_object_to_library(library, name, type_obj)
        exported.append(name)
    if not library.finalize():
        raise mcp.ToolError(
            "finalize_failed", f"could not finalize type library '{_truncate(library_name)}'"
        )
    resolved = _resolve_export_path(filename)
    try:
        library.write_to_file(str(resolved))
        bytes_written = resolved.stat().st_size
    except OSError as error:
        raise mcp.ToolError("export_failed", f"could not write export file: {error}") from None
    if bytes_written > _MAX_EXPORT_FILE_BYTES:
        with contextlib.suppress(OSError):
            resolved.unlink()
        raise mcp.ToolError(
            "export_failed",
            f"type library file exceeds the {_MAX_EXPORT_FILE_BYTES} byte export cap",
        )
    return {
        "path": str(resolved),
        "bytes_written": bytes_written,
        "library": _truncate(library_name),
        "exported": exported,
        "failed": failed,
        "total": len(names),
    }


@mcp.tool()
def rex_type_library_import(call: mcp.ToolCall, path: str, names: list[str]) -> dict[str, object]:
    """Import types from a .bntl into the current binary view.

    Loads the type library file, attaches it to the view (``bv.add_type_library``, making
    its contents available for type/import resolution) and imports each requested name
    (``bv.import_library_type``), which recursively pulls in dependency libraries the
    types reference. Importing a name defines it in the view as an auto type, so this is
    additive: on a name conflict the core deconflicts rather than overwriting, and the
    response's ``resolved`` field carries the name actually inserted, which may differ
    from the requested one. A name the library does not provide is reported per-name
    under ``failed`` — the other names still import.

    Reads whatever path the caller supplies; only the type-system state of the view
    changes. Bounded: 1 to 64 names per call, each at most 255 characters.

    :param path: Filesystem path of the .bntl file to load.
    :param names: Type names to import from the library; 1 to 64 entries.
    """
    bv = call.binary_view
    _validate_type_names(names)
    library = TypeLibrary.load_from_file(path)
    if library is None:
        raise mcp.ToolError(
            "library_not_found", f"could not load a type library from '{_truncate(path)}'"
        )
    bv.add_type_library(library)
    imported: list[dict[str, str]] = []
    failed: list[dict[str, str]] = []
    for name in names:
        type_obj = bv.import_library_type(name, library)
        if type_obj is None:
            failed.append({"requested": name, "reason": "not provided by this type library"})
            continue
        # The return value is a NamedTypeReference whose name is the deconflicted name
        # the core actually inserted.
        imported.append({"requested": name, "resolved": str(type_obj.name)})
    return {
        "library": _truncate(library.name) if library.name is not None else None,
        "imported": imported,
        "failed": failed,
        "total": len(names),
    }


@mcp.tool(destructive=True)
def rex_undo(call: mcp.ToolCall) -> dict[str, object]:
    """Undo the last committed transaction in the view's undo database.

    The rollback for the plugin's destructive tools: one rex_undo step reverses one
    whole rex_annotate_many batch, a rex_memory_write, and anything else committed as
    a transaction. The stack is shared with the GUI user, so this may roll back their
    most recent edit too. An empty stack is a core-side no-op, not an error — the
    post-operation ``undo_left``/``redo_left`` depths let a caller stop when ``undo_left``
    stops changing.
    """
    try:
        call.binary_view.undo()
    except Exception as error:
        raise mcp.ToolError("undo_failed", f"could not undo: {error}") from None
    return {
        "undone": True,
        "undo_left": len(call.binary_view.file.undo_entries),
        "redo_left": len(call.binary_view.file.redo_entries),
    }
