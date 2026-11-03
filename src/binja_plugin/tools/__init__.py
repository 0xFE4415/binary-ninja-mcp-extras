"""MCP tools extending Binary Ninja's built-in MCP server.

Every tool is prefixed ``rex_`` because the ``bn_`` prefix belongs to the built-in tools.
Handlers run on the MCP server thread, so none of them touch the UI thread directly.

The handlers live in the per-category modules imported at the bottom of this file, and
importing this package registers all of them. The shared helpers stay defined above
those imports: the category modules import them from this namespace, and the property
tests patch ``_READ_CHUNK``/``_EXPORT_ROOT`` as module globals of ``binja_plugin.tools``.
"""

import re
from bisect import bisect_right
from collections.abc import Callable, Iterable, Iterator
from itertools import islice
from pathlib import Path
from typing import Any

from binaryninja import mcp
from binaryninja.binaryview import BinaryView
from binaryninja.function import Function

_READ_CHUNK = 4 * 1024 * 1024
_MAX_CHARS = 512
# Hard caps for list sizes and echoed strings: user-supplied size parameters are
# range-checked against these in the tool bodies — matching the schema-side
# Minimum/Maximum annotations — so out-of-range values are rejected even when handlers
# are invoked directly.
_MAX_LIMIT = 500

# rex_disasm_at window sizes: bounded so one call can never request an unbounded
# instruction render, whatever the containing function's size.
_MAX_DISASM_CONTEXT = 64

# rex_export_* tools: sweeps write to one fixed directory and echo only a summary, so a
# large export can never flood the MCP response. The byte cap bounds each file; the
# window caps bound how much a single call selects before serialization.
_EXPORT_ROOT = Path.home() / ".binaryninja" / "exports"
_MAX_EXPORT_COMPONENT_BYTES = 255
_MAX_EXPORT_FILE_BYTES = 4 * 1024 * 1024


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


def _validate_text(name: str, value: str, maximum: int, too_large_code: str) -> str:
    """Reject an empty or over-cap string argument instead of silently normalizing it."""
    if not value:
        raise mcp.ToolError("invalid_params", f"{name} must not be empty")
    if len(value) > maximum:
        raise mcp.ToolError(too_large_code, f"{name} exceeds {maximum} characters")
    return value


def _truncate_with_flag(value: str, limit: int = _MAX_CHARS) -> tuple[str, bool]:
    if len(value) <= limit:
        return value, False
    return value[:limit] + f"... [{len(value) - limit} chars truncated]", True


def _truncate(value: str, limit: int = _MAX_CHARS) -> str:
    return _truncate_with_flag(value, limit)[0]


def _compile_user_regex(pattern: str, ignore_case: bool = False) -> re.Pattern[str]:
    # Compilation and matching run on Python's re with no timeout, so a pattern with
    # catastrophic backtracking can stall the scan; untrusted input belongs in
    # substring mode.
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


def _skip(iterator: Iterator[object], offset: int) -> int:
    """Consume and discard up to ``offset`` items, returning how many actually existed."""
    # zip over range, not islice: the offset is unbounded and islice rejects values
    # above sys.maxsize.
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


def _require_containing_function(
    bv: BinaryView, address: int, code: str, described: str
) -> Function:
    """Return the function containing ``address``, or reject with the caller's convention.

    ``code`` is deliberate: scan-style tools answer ``no_function`` for a containment
    miss, argument-validating tools treat the same miss as ``invalid_params``.
    """
    functions = bv.get_functions_containing(address)
    if not functions:
        raise mcp.ToolError(code, f"no {described} contains {address:#x}")
    return functions[0]


def _require_analyzed_function(bv: BinaryView, address: int) -> Function:
    return _require_containing_function(bv, address, "invalid_params", "analyzed function")


def _resolve_address_batch(
    call: mcp.ToolCall, bv: BinaryView, functions: object, maximum: int
) -> list[Function]:
    """Resolve a tool's ``functions`` list of address expressions to analyzed functions.

    Every entry is resolved before anything is handed back, so a bad entry anywhere in
    the batch cannot leave a partial result behind.
    """
    if not isinstance(functions, list):
        raise mcp.ToolError("invalid_params", "functions must be a list of address expressions")
    if not 1 <= len(functions) <= maximum:
        raise mcp.ToolError(
            "invalid_params",
            f"functions must contain between 1 and {maximum} address expressions",
        )
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
    return resolved


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
    return _require_containing_function(bv, address, "no_function", "function")


def _function_entry(function: Function) -> dict[str, object]:
    return {"start": hex(function.start), "name": _truncate(function.name)}


def _render_function_disassembly(function: Any) -> list[tuple[int, str]]:
    """Render a function's addressed disassembly lines, sorted by address.

    Shared by rex_disasm_at and rex_export_disasm so both tools see the same render;
    Any-typed because the stubbed Function type does not model basic_blocks.
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
    """Join an already-validated filename with the export root and resolve it.

    The containment check must run after resolve(): a symlink planted inside the
    export root would otherwise redirect the write outside it, past the lexical checks.
    """
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
    dropped = False
    while True:
        text = serialize(window)
        if len(text.encode("utf-8")) <= _MAX_EXPORT_FILE_BYTES:
            return text, dropped
        del window[-1]
        dropped = True


# The category modules import the shared helpers defined above from this namespace, so
# these imports must stay below those definitions. Importing them registers every tool
# with the mcp layer; the re-exports keep ``binja_plugin.tools.<name>`` working exactly
# as it did when the tools lived in one module — including the per-tool caps the
# property tests read through this namespace.

from .analysis import rex_analysis_wait, rex_binary_close
from .annotations import rex_annotate_many
from .components import (
    rex_component_add_functions,
    rex_component_create,
    rex_component_get,
)
from .decompile import (
    _MAX_HLIL_GREP_CONTEXT,
    _MAX_HLIL_GREP_LIMIT,
    rex_decompile_many,
    rex_disasm_at,
    rex_hlil_grep,
    rex_quick_main,
)
from .escape import rex_eval_python, rex_memory_write
from .exports import _MAX_EXPORT_SYMBOLS, rex_export_disasm, rex_export_symbols
from .functions import (
    _MAX_CALL_PATH_DEPTH,
    _MAX_CALL_PATHS,
    rex_call_paths,
    rex_function_containing,
    rex_function_define,
    rex_function_undefine,
)
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
