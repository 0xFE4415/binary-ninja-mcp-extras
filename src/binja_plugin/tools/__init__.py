"""MCP tools extending Binary Ninja's built-in MCP server.

Every tool is prefixed ``rex_`` because the ``bn_`` prefix belongs to the built-in tools.
Handlers run on the MCP server thread, so none of them touch the UI thread directly.

The handlers live in the per-category modules imported at the bottom of this file, and
importing this package registers all of them. The shared helpers stay defined above
those imports: the category modules import them from this namespace, and the property
tests patch ``_READ_CHUNK``/``_EXPORT_ROOT`` as module globals of ``binja_plugin.tools``.
"""

import re
import time
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Iterable, Iterator
from itertools import islice
from pathlib import Path
from typing import Literal, NamedTuple, NoReturn, TypedDict, TypeIs

from binaryninja import mcp, user_directory
from binaryninja.binaryview import BinaryView
from binaryninja.enums import AnalysisSkipReason, AnalysisState
from binaryninja.function import Function

_READ_CHUNK = 4 * 1024 * 1024
_MAX_CHARS = 512
# Range-checked in the tool bodies as well as the schema, so direct handler calls are bounded.
_MAX_LIMIT = 500

# Bounds the candidate names an error message echoes, so one misspelled name cannot flood it.
_MAX_NAME_CANDIDATES = 40

_MAX_DISASM_CONTEXT = 4096

_MAX_RESOLUTION_ALTERNATIVES = 64
_ANALYSIS_SLICE_MS = 100
_MAX_ANALYSIS_WAIT_MS = 10000


def _default_export_root() -> Path:
    user_root = user_directory()
    if user_root is None or user_root == "":
        return Path.home() / ".binaryninja" / "exports"
    return Path(user_root) / "exports"


# Export sweeps write to one fixed directory and echo only a summary.
_EXPORT_ROOT = _default_export_root()
_MAX_EXPORT_COMPONENT_BYTES = 255
_MAX_EXPORT_FILE_BYTES = 4 * 1024 * 1024


def _is_json_object(value: object) -> TypeIs[dict[str, object]]:
    return isinstance(value, dict)


def _validate_range(name: str, value: int, minimum: int, maximum: int | None = None) -> int:
    """Reject an out-of-range integer argument instead of silently normalizing it."""
    if value < minimum:
        raise mcp.ToolError(
            "invalid_params", f"Invalid integer parameter '{name}': Must be at least {minimum}"
        )
    if maximum is not None and value > maximum:
        raise mcp.ToolError(
            "invalid_params", f"Invalid integer parameter '{name}': Must be at most {maximum}"
        )
    return value


def _nul_message(parameter: str) -> str:
    return f"{parameter} must not contain NUL bytes"


def _reject_nul(parameter: str, value: str) -> None:
    if "\x00" in value:
        raise mcp.ToolError("invalid_params", _nul_message(parameter))


def _validate_text(name: str, value: str, maximum: int, too_large_code: str) -> str:
    """Reject an empty, NUL-bearing, or over-cap string argument instead of normalizing it."""
    if not value:
        raise mcp.ToolError("invalid_params", f"{name} must not be empty")
    _reject_nul(name, value)
    if len(value) > maximum:
        raise mcp.ToolError(too_large_code, f"{name} exceeds {maximum} characters")
    return value


def _truncate_with_flag(value: str, limit: int = _MAX_CHARS) -> tuple[str, bool]:
    if len(value) <= limit:
        return value, False
    return value[:limit] + f"... [{len(value) - limit} chars truncated]", True


def _truncate(value: str, limit: int = _MAX_CHARS) -> str:
    return _truncate_with_flag(value, limit)[0]


def _compile_user_regex(
    parameter: Literal["pattern", "regex", "function_filter"],
    pattern: str,
    ignore_case: bool = False,
) -> re.Pattern[str]:
    # re has no timeout and can backtrack forever, so untrusted input belongs in substring mode.
    flags = re.IGNORECASE if ignore_case else 0
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise mcp.ToolError(
            "invalid_regex", f"Invalid regular expression parameter '{parameter}': {exc}"
        ) from None


def _name_filter(function_filter: str) -> re.Pattern[str] | None:
    if not function_filter:
        return None
    return _compile_user_regex("function_filter", function_filter, ignore_case=True)


def _show_nul(text: str) -> str:
    # The core cuts a message at its first NUL, so an echoed NUL must not reach it.
    return text.replace("\x00", "\N{REPLACEMENT CHARACTER}")


def _resolve_section(bv: BinaryView, name: str) -> tuple[int, int]:
    # The core reads the name as a C string, so a NUL would silently select a shorter name.
    section = None if "\x00" in name else bv.get_section_by_name(name)
    if section is None:
        raise mcp.ToolError("section_not_found", f"no section named '{_show_nul(_truncate(name))}'")
    return section.start, section.end


def _skip(iterator: Iterator[object], offset: int) -> int:
    """Consume and discard up to ``offset`` items, returning how many actually existed."""
    # zip over range, not islice: islice rejects offsets above sys.maxsize.
    return sum(1 for _ in zip(range(offset), iterator))


def _drop[Item](items: Iterable[Item], offset: int) -> Iterator[Item]:
    """Yield the items of ``items`` past the first ``offset``."""
    iterator = iter(items)
    _skip(iterator, offset)
    return iterator


def _paginate[Item](items: Iterable[Item], offset: int, limit: int) -> tuple[list[Item], int, bool]:
    """Return the ``[offset, offset + limit)`` page, the count seen, and whether more exist."""
    iterator = iter(items)
    skipped = _skip(iterator, offset)
    page = list(islice(iterator, limit))
    truncated = bool(list(islice(iterator, 1)))
    return page, skipped + len(page) + int(truncated), truncated


def _containment_miss_hint(bv: BinaryView, address: int, advise_define: bool) -> str:
    if not bv.is_valid_offset(address):
        return "the address is not mapped by any segment"
    # Overlapping functions can hide the owner of address - 1, so check every one containing it.
    previous = next(
        (
            candidate
            for candidate in bv.get_functions_containing(address - 1)
            if candidate.highest_address + 1 == address
        ),
        None,
    )
    define_call = f"rex_function_define(start={address:#x})"
    if previous is None:
        diagnosis = "the address is mapped but no function covers it"
        if not advise_define:
            return diagnosis
        return f"{diagnosis}; define one with {define_call} if it is code"
    diagnosis = (
        f"the address is immediately past the end of {_truncate(previous.name)} at "
        f"{previous.start:#x} (highest address {previous.highest_address:#x}); when the last "
        "instruction ends the block (for example int3, ret, or jmp) the next bytes belong to "
        "no function"
    )
    if not advise_define:
        return diagnosis
    return f"{diagnosis}, so define one with {define_call} if execution continues"


def _containment_miss(
    bv: BinaryView, address: int, described: str, advise_define: bool = True
) -> tuple[bool, str]:
    # A defined but unanalyzed function is invisible to containment lookups.
    if bv.get_function_at(address) is not None:
        wait_advice = "rex_analysis_wait, or rex_function_define with wait=true"
        if not advise_define:
            wait_advice = "rex_analysis_wait"
        return True, (
            f"function at {address:#x} exists but has not been analyzed yet; wait for "
            f"analysis ({wait_advice}) or run bn_analysis_update"
        )
    message = f"no {described} contains {address:#x}"
    return False, f"{message}; {_containment_miss_hint(bv, address, advise_define)}"


def _raise_containment_miss(
    bv: BinaryView, address: int, code: str, described: str, advise_define: bool = True
) -> NoReturn:
    pending, message = _containment_miss(bv, address, described, advise_define)
    raise mcp.ToolError("analysis_pending" if pending else code, message)


class _FunctionEntry(TypedDict):
    start: str
    name: str


def _function_entry(function: Function) -> _FunctionEntry:
    return {"start": hex(function.start), "name": _truncate(function.name)}


class _ResolvedFunction(_FunctionEntry):
    also_containing: list[_FunctionEntry]
    same_name: list[_FunctionEntry]


class _Resolution(NamedTuple):
    function: Function
    entry: _ResolvedFunction


def _function_order(function: Function) -> tuple[int, str]:
    return function.start, function.arch.name


def _resolved_entry(
    bv: BinaryView, chosen: Function, containing: list[Function]
) -> _ResolvedFunction:
    also_containing = sorted(
        (other for other in containing if other != chosen), key=_function_order
    )
    same_name = sorted(
        (other for other in bv.get_functions_by_name(chosen.name) if other != chosen),
        key=_function_order,
    )
    return {
        **_function_entry(chosen),
        "also_containing": [
            _function_entry(other) for other in also_containing[:_MAX_RESOLUTION_ALTERNATIVES]
        ],
        "same_name": [_function_entry(other) for other in same_name[:_MAX_RESOLUTION_ALTERNATIVES]],
    }


def _functions_needing_update(bv: BinaryView) -> list[Function]:
    return [function for function in bv.functions if function.needs_update]


def _analysis_settled(bv: BinaryView, functions: list[Function]) -> bool:
    # The view can still read idle right after update_analysis; a stale function knows better.
    if bv.analysis_progress.state != AnalysisState.IdleState:
        return False
    return not any(function.needs_update for function in functions)


def _refresh_analysis(bv: BinaryView, functions: list[Function]) -> bool:
    """Start reanalysis and wait, bounded, for ``functions``; False when the deadline passes."""
    bv.update_analysis()
    deadline = time.monotonic() + _MAX_ANALYSIS_WAIT_MS / 1000
    settled = _analysis_settled(bv, functions)
    while not settled and time.monotonic() < deadline:
        time.sleep(_ANALYSIS_SLICE_MS / 1000)
        settled = _analysis_settled(bv, functions)
    return settled


def _resolve_containing(bv: BinaryView, containing: list[Function]) -> _Resolution:
    """Pick the containing function with the lowest start, architecture name breaking ties."""
    chosen = min(containing, key=_function_order)
    return _Resolution(chosen, _resolved_entry(bv, chosen, containing))


def _require_containing_function(
    bv: BinaryView, address: int, code: str, described: str, advise_define: bool = True
) -> _Resolution:
    # Scan tools answer no_function for a miss, argument validators invalid_params.
    containing = bv.get_functions_containing(address)
    if not containing:
        _raise_containment_miss(bv, address, code, described, advise_define)
    return _resolve_containing(bv, containing)


_SKIP_CAUSES: dict[AnalysisSkipReason, str] = {
    AnalysisSkipReason.NoSkipReason: "the core reports no reason",
    AnalysisSkipReason.AlwaysSkipReason: "its analysis_skip_override always skips it",
    AnalysisSkipReason.ExceedFunctionSizeSkipReason: (
        "it exceeds the analysis.limits.maxFunctionSize limit"
    ),
    AnalysisSkipReason.ExceedFunctionAnalysisTimeSkipReason: (
        "its analysis exceeded the analysis.limits.maxFunctionAnalysisTime limit"
    ),
    AnalysisSkipReason.ExceedFunctionUpdateCountSkipReason: (
        "its analysis exceeded the analysis.limits.maxFunctionUpdateCount limit"
    ),
    AnalysisSkipReason.NewAutoFunctionAnalysisSuppressedReason: (
        "analysis of newly found functions is suppressed (analysis.suppressNewAutoFunctionAnalysis)"
    ),
    AnalysisSkipReason.BasicAnalysisSkipReason: "analysis.mode is basic",
    AnalysisSkipReason.IntermediateAnalysisSkipReason: "analysis.mode is intermediate",
    AnalysisSkipReason.AnalysisPipelineSuspendedReason: "the analysis pipeline is suspended",
}


def _missing_il_message(function: Function, level: Literal["MediumLevelIL", "HLIL"]) -> str:
    """Explain a missing IL: a skipped function never gets one, a pending one will."""
    name = _truncate(function.name)
    if function.analysis_skipped:
        cause = _SKIP_CAUSES[function.analysis_skip_reason]
        return (
            f"function {name} has no {level}: its analysis is skipped ({cause}); "
            "waiting for analysis will not produce one"
        )
    return (
        f"function {name} has no {level} yet; "
        "run bn_analysis_update_and_wait (or rex_analysis_wait with a bound) and retry"
    )


def _missing_il_error(
    function: Function, level: Literal["MediumLevelIL", "HLIL"], code: Literal["no_mlil", "no_hlil"]
) -> mcp.ToolError:
    return mcp.ToolError(code, _missing_il_message(function, level))


def _unknown_variable_error(function: Function, name: str) -> mcp.ToolError:
    names = sorted({variable.name for variable in function.vars})
    shown = ", ".join(_truncate(candidate, 64) for candidate in names[:_MAX_NAME_CANDIDATES])
    more = (
        f" (+{len(names) - _MAX_NAME_CANDIDATES} more)" if len(names) > _MAX_NAME_CANDIDATES else ""
    )
    return mcp.ToolError(
        "no_variable",
        f"no MLIL variable named '{_show_nul(_truncate(name))}' in {_truncate(function.name)}; "
        f"variables: {shown}{more}; use bn_variable_list for the full list",
    )


def _require_analyzed_function(bv: BinaryView, address: int) -> _Resolution:
    return _require_containing_function(bv, address, "invalid_params", "analyzed function")


def _parse_address_entry(call: mcp.ToolCall, index: int, entry: object, noun: str) -> int:
    """Parse one entry of a tool's address-expression list to an integer."""
    if not isinstance(entry, str):
        raise mcp.ToolError(
            "invalid_params", f"{noun}[{index}] must be a string address expression"
        )
    _reject_nul(f"{noun}[{index}]", entry)
    try:
        return call.parse_address(entry)
    except Exception as error:
        raise mcp.ToolError(
            "invalid_params", f"bad address expression '{_truncate(entry)}': {error}"
        ) from None


def _require_address_list(entries: object, maximum: int, noun: str) -> list[object]:
    if not isinstance(entries, list):
        raise mcp.ToolError("invalid_params", f"{noun} must be a list of address expressions")
    if not 1 <= len(entries) <= maximum:
        raise mcp.ToolError(
            "invalid_params",
            f"{noun} must contain between 1 and {maximum} address expressions",
        )
    return list(entries)


def _parse_address_batch(call: mcp.ToolCall, entries: object, maximum: int, noun: str) -> list[int]:
    entries = _require_address_list(entries, maximum, noun)
    return [_parse_address_entry(call, index, entry, noun) for index, entry in enumerate(entries)]


def _resolve_address_pairs(
    call: mcp.ToolCall, bv: BinaryView, addresses: object, maximum: int, noun: str
) -> list[tuple[int, _Resolution]]:
    """Resolve a tool's list of address expressions to (address, analyzed function) pairs."""
    return [
        (address, _require_analyzed_function(bv, address))
        for address in _parse_address_batch(call, addresses, maximum, noun)
    ]


def _resolve_address_batch(
    call: mcp.ToolCall, bv: BinaryView, functions: object, maximum: int
) -> list[_Resolution]:
    """Resolve a tool's ``functions`` list of address expressions to analyzed functions."""
    pairs = _resolve_address_pairs(call, bv, functions, maximum, "functions")
    return [function for _, function in pairs]


def _iter_pattern_matches(
    bv: BinaryView,
    matcher: re.Pattern[bytes],
    pattern_length: int,
    bounds: tuple[int, int] | None = None,
) -> Iterator[int]:
    """Yield absolute match addresses, optionally clipped to a section range."""
    for segment in bv.segments:
        # Skipping an unreadable segment saves the whole walk, not just the reads.
        if not segment.readable:
            continue
        start, end = int(segment.start), segment.start + segment.length
        if bounds is not None:
            start = max(start, bounds[0])
            end = min(end, bounds[1])
        position = start
        read = bv.read
        finditer = matcher.finditer
        while position < end:
            read_size = min(_READ_CHUNK + pattern_length - 1, end - position)
            chunk = read(position, read_size)
            if chunk:
                for match in finditer(chunk):
                    yield position + match.start()
            position += _READ_CHUNK


def _require_function(bv: BinaryView, address: int, advise_define: bool = True) -> _Resolution:
    return _require_containing_function(bv, address, "no_function", "function", advise_define)


class _ItemError(TypedDict):
    code: str
    message: str


def _render_function_disassembly(function: Function) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for block in function.basic_blocks:
        for line in block.get_disassembly_text():
            if line.address is not None:
                lines.append((line.address, "".join(str(token) for token in line.tokens)))
    return sorted(lines, key=lambda entry: entry[0])


def _disasm_window(
    lines: list[tuple[int, str]], address: int, before: int, after: int
) -> tuple[int, int]:
    """Return the [start, end) slice of ``lines`` for the before/after window at ``address``."""
    # The anchor is the last line at or before the address: at a shared one, the instruction.
    anchor = max(bisect_right(lines, address, key=lambda entry: entry[0]) - 1, 0)
    start = max(0, anchor - before)
    end = min(len(lines), anchor + 1 + after)
    return start, end


def _validate_disasm_window(before: int, after: int) -> tuple[int, int]:
    """Range-check the shared before/after window parameters of the disasm tools."""
    before = _validate_range("before", before, 0, _MAX_DISASM_CONTEXT)
    after = _validate_range("after", after, 0, _MAX_DISASM_CONTEXT)
    return before, after


def _validate_export_path(filename: str) -> None:
    """Reject, purely lexically, filenames that could escape or abuse the export root."""
    if not filename:
        raise mcp.ToolError("invalid_params", "filename must not be empty")
    if filename.startswith("/"):
        raise mcp.ToolError(
            "invalid_params", "filename must be a plain file name, not an absolute path"
        )
    if "\\" in filename:
        raise mcp.ToolError("invalid_params", "filename must not contain backslashes")
    _reject_nul("filename", filename)
    parts = filename.split("/")
    if ".." in parts:
        raise mcp.ToolError("invalid_params", "filename must not contain '..' path components")
    if parts[-1] in ("", "."):
        raise mcp.ToolError(
            "invalid_params", "filename must end in a file name, not '.' or a trailing '/'"
        )
    for part in parts:
        if len(part.encode("utf-8")) > _MAX_EXPORT_COMPONENT_BYTES:
            # NAME_MAX applies per component, not to the joined path.
            raise mcp.ToolError(
                "invalid_params",
                f"filename component exceeds {_MAX_EXPORT_COMPONENT_BYTES} bytes",
            )


def _reject_unusable_export_target(filename: str) -> None:
    resolved_root = _EXPORT_ROOT.resolve()
    resolved = (_EXPORT_ROOT / filename).resolve()
    if not resolved.is_relative_to(resolved_root):
        return
    if resolved.is_dir():
        raise mcp.ToolError(
            "invalid_params", "filename names an existing directory; choose a file name"
        )
    if resolved.parent != resolved_root and not resolved.parent.is_dir():
        raise mcp.ToolError(
            "invalid_params",
            "the parent of filename is not an existing directory; "
            "use a plain file name in the export root",
        )


def _resolve_export_path(filename: str) -> Path:
    # Containment is checked after resolve(): a symlink inside the root must not redirect the write.
    try:
        _EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
        resolved_root = _EXPORT_ROOT.resolve()
        resolved = (_EXPORT_ROOT / filename).resolve()
    except (OSError, ValueError) as error:
        raise mcp.ToolError("export_failed", f"could not prepare export path: {error}") from None
    if not resolved.is_relative_to(resolved_root):
        raise mcp.ToolError("path_escape", f"filename resolves outside the export root: {resolved}")
    return resolved


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
    """Serialize a result window, dropping trailing entries until it fits the byte cap."""
    if window and len(serialize(window[:1]).encode("utf-8")) > _MAX_EXPORT_FILE_BYTES:
        raise mcp.ToolError("export_failed", "first entry exceeds the export byte cap")
    text = serialize(window)
    if len(text.encode("utf-8")) <= _MAX_EXPORT_FILE_BYTES:
        return text, False
    fitting = bisect_left(
        range(1, len(window)),
        _MAX_EXPORT_FILE_BYTES + 1,
        key=lambda length: len(serialize(window[:length]).encode("utf-8")),
    )
    del window[fitting:]
    return serialize(window), True


# These imports register every tool and must stay below the helpers they import from here.

from .analysis import rex_analysis_wait, rex_binary_close
from .annotations import rex_annotate_many
from .components import (
    rex_component_add_functions,
    rex_component_create,
    rex_component_get,
)
from .data import rex_data_read, rex_relocation_at, rex_xrefs_to
from .dataflow import (
    rex_function_constraints,
    rex_hlil_statements,
    rex_mlil_uses,
    rex_parameter_variables,
)
from .decompile import (
    _MAX_DECOMPILE_LINES,
    _MAX_HLIL_GREP_CONTEXT,
    _MAX_HLIL_GREP_LIMIT,
    _render_hlil_lines,
    rex_decompile_many,
    rex_disasm_at,
    rex_disasm_many,
    rex_hlil_grep,
)
from .escape import rex_eval_python, rex_eval_result, rex_memory_write
from .exports import _MAX_EXPORT_SYMBOLS, rex_export_disasm, rex_export_symbols
from .functions import (
    _MAX_CALL_PATH_DEPTH,
    _MAX_CALL_PATHS,
    rex_call_paths,
    rex_function_containing,
    rex_function_define,
    rex_function_define_many,
    rex_function_undefine,
)
from .help import rex_help
from .scanning import (
    _MAX_FIND_FUNCTIONS_EXAMPLES,
    rex_constant_find,
    rex_data_find,
    rex_find_functions_by_pattern,
)
from .state import (
    rex_kv_delete,
    rex_kv_get,
    rex_kv_set,
    rex_redo,
    rex_report_show,
    rex_tag_list,
    rex_tag_set,
    rex_undo,
)
from .strings import (
    rex_string_read_at,
    rex_string_refs,
    rex_string_search,
)
from .types import (
    rex_struct_from_access,
    rex_type_library_export,
    rex_type_library_import,
)
from .uidf import rex_uidf_clear, rex_uidf_list, rex_uidf_set, rex_uidf_set_many
