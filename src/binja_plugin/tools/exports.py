"""Anti-flood file exports: disassembly windows and symbol tables written to disk."""

from __future__ import annotations

import csv
import io
import json
from typing import Annotated, Literal, NamedTuple, TypedDict

from binaryninja import mcp

from binja_plugin.tools import (
    _MAX_DISASM_CONTEXT,
    _disasm_window,
    _fit_to_export_cap,
    _reject_unusable_export_target,
    _render_function_disassembly,
    _require_analyzed_function,
    _resolve_export_path,
    _ResolvedFunction,
    _show_nul,
    _validate_export_path,
    _validate_range,
    _write_export_file,
)

_MAX_EXPORT_DISASM_LINES = 2 * _MAX_DISASM_CONTEXT + 1
_MAX_EXPORT_SYMBOLS = 2048

ExportFormat = Literal["csv", "json"]


class _SymbolRow(NamedTuple):
    address: int
    symbol_type: str
    name: str


class _ExportDisasmResult(TypedDict):
    function: _ResolvedFunction
    path: str
    bytes_written: int
    lines: int
    truncated: bool


class _ExportSymbolsResult(TypedDict):
    path: str
    bytes_written: int
    rows: int
    truncated: bool
    total: int


def _symbols_csv(rows: list[_SymbolRow]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["symbol_address", "symbol_type", "name"])
    for row in rows:
        writer.writerow([hex(row.address), row.symbol_type, row.name])
    return buffer.getvalue()


def _symbols_json(rows: list[_SymbolRow]) -> str:
    return json.dumps(
        [
            {"symbol_address": hex(row.address), "symbol_type": row.symbol_type, "name": row.name}
            for row in rows
        ],
        indent=2,
    )


@mcp.tool(destructive=True)
def rex_export_disasm(
    call: mcp.ToolCall,
    address: mcp.Address,
    filename: str,
    before: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 4,
    after: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 8,
    max_lines: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_EXPORT_DISASM_LINES)] = 200,
) -> _ExportDisasmResult:
    """Write a function's disassembly window to a file as "0xADDR  text" lines; returns the path.

    :param address: Address expression inside the target function.
    :param filename: Plain file name inside the export root; overwritten if it exists.
    :param before: Instructions to include before the anchor.
    :param after: Instructions to include after the anchor.
    :param max_lines: Maximum lines to export.
    """
    bv = call.binary_view
    _validate_export_path(filename)
    _reject_unusable_export_target(filename)
    resolution = _require_analyzed_function(bv, address)
    lines = _render_function_disassembly(resolution.function)
    start, end = _disasm_window(lines, address, before, after)
    window = lines[start:end][:max_lines]

    def serialize(selected: list[tuple[int, str]]) -> str:
        return "".join(f"{hex(line_address)}  {text}\n" for line_address, text in selected)

    text, dropped = _fit_to_export_cap(serialize, window)
    resolved = _resolve_export_path(filename)
    return {
        "function": resolution.entry,
        "path": str(resolved),
        "bytes_written": _write_export_file(resolved, text),
        "lines": len(window),
        "truncated": len(window) < len(lines) or dropped,
    }


@mcp.tool(destructive=True)
def rex_export_symbols(
    call: mcp.ToolCall,
    start: mcp.IntegerExpression,
    end: mcp.IntegerExpression,
    filename: str,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_EXPORT_SYMBOLS)] = 500,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
    format: ExportFormat = "csv",
) -> _ExportSymbolsResult:
    """Export the symbols in an address range to a file.

    :param start: Range start, inclusive; an integer or address expression string.
    :param end: Range end, exclusive, above ``start``; an integer or address expression string.
    :param filename: Plain file name inside the export root; overwritten if it exists.
    :param limit: Maximum symbols to export.
    :param offset: Sorted symbols to skip before the window starts.
    :param format: Output format, "csv" or "json".
    """
    bv = call.binary_view
    # The core rejects negatives first; this guards direct handler calls.
    _validate_range("start", start, 0)
    if start >= end:
        raise mcp.ToolError("invalid_params", "end must be greater than start")
    _validate_export_path(filename)
    _reject_unusable_export_target(filename)
    # Widened to str so the body check stays reachable by direct calls; match the Literal.
    requested: str = format
    if requested not in ("csv", "json"):
        raise mcp.ToolError(
            "invalid_params", f"format must be 'csv' or 'json', not '{_show_nul(requested)}'"
        )
    symbols = bv.get_symbols(start, end - start)
    # Core symbol order is unsorted; sort before slicing so the file holds a true window.
    ordered = sorted(symbols, key=lambda symbol: symbol.address)
    total = len(ordered)
    window = [
        _SymbolRow(symbol.address, symbol.type.name, symbol.name)
        for symbol in ordered[offset : offset + limit]
    ]
    serialize = _symbols_csv if requested == "csv" else _symbols_json

    text, dropped = _fit_to_export_cap(serialize, window)
    resolved = _resolve_export_path(filename)
    return {
        "path": str(resolved),
        "bytes_written": _write_export_file(resolved, text),
        "rows": len(window),
        "truncated": offset + limit < total or dropped,
        "total": total,
    }
