"""Anti-flood file exports: disassembly windows and symbol tables written to disk."""

from __future__ import annotations

import csv
import io
import json
from typing import Annotated, Literal

from binaryninja import mcp

from binja_plugin.tools import (
    _MAX_DISASM_CONTEXT,
    _disasm_window,
    _fit_to_export_cap,
    _render_function_disassembly,
    _require_analyzed_function,
    _resolve_export_path,
    _validate_disasm_window,
    _validate_export_path,
    _validate_range,
    _write_export_file,
)

_MAX_EXPORT_DISASM_LINES = 400
_MAX_EXPORT_SYMBOLS = 2000

_EXPORT_FORMATS = Literal["csv", "json"]


@mcp.tool(destructive=True)
def rex_export_disasm(
    call: mcp.ToolCall,
    address: mcp.Address,
    before: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 4,
    after: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 8,
    max_lines: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_EXPORT_DISASM_LINES)] = 200,
    filename: str = "",
) -> dict[str, object]:
    """Export one analyzed function's disassembly window to a file.

    :param address: Address expression inside the target function.
    :param before: Instructions to include before the anchor.
    :param after: Instructions to include after the anchor.
    :param max_lines: Maximum lines to export.
    :param filename: Plain file name inside the export root; overwritten if it exists.
    """
    bv = call.binary_view
    before, after = _validate_disasm_window(before, after)
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


@mcp.tool(destructive=True)
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

    :param start: Start of the address range, inclusive.
    :param end: End of the address range, exclusive; must be greater than ``start``.
    :param limit: Maximum symbols to export.
    :param offset: Sorted symbols to skip before the window starts.
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
    # a true window of the address-ordered listing, not an unsorted first-fit subset.
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
