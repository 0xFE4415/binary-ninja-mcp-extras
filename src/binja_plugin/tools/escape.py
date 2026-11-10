"""Unmediated view operations the structured tools do not cover.

rex_eval_python runs trusted code against the Binary Ninja API and rex_memory_write
patches raw bytes: both bypass the abstractions the other tools wrap around the core.
"""

from __future__ import annotations

import contextlib
import io
import itertools
import re
import traceback
from collections import OrderedDict
from typing import Annotated

import binaryninja
from binaryninja import mcp

from binja_plugin.tools import _truncate, _truncate_with_flag, _validate_range

_MAX_EVAL_STDOUT_CHARS = 65536
_MAX_EVAL_RESULT_CHARS = 16384
_MAX_EVAL_LOCATION_CHARS = 200
_EVAL_FILENAME = "<rex_eval_python>"

# Spilled oversized echoes: when rex_eval_python's stdout or result is clipped, the full
# text is kept in process memory (never the view's database) so rex_eval_result can page
# it back. The store keeps the most recent few spills and dies with the server process;
# a spill larger than the per-spill cap is not kept at all, and the clipped echo is then
# the only copy.
_MAX_EVAL_SPILLS = 8
_MAX_EVAL_SPILL_CHARS = 4 * 1024 * 1024
_MAX_EVAL_RESULT_PAGE_CHARS = 65536
_EVAL_SPILLS: OrderedDict[str, str] = OrderedDict()
_SPILL_SEQUENCE = itertools.count()


def _spill_echo(text: str, cap: int, kind: str) -> tuple[str, bool, str | None, int]:
    """Echo ``text`` clipped to ``cap`` characters, spilling the full text when clipped.

    Returns (echo, truncated, spill_key, total_length). The spill key is set only when
    the full text is retrievable through rex_eval_result.
    """
    if len(text) <= cap:
        return text, False, None, len(text)
    echo = text[:cap] + f"... [{len(text) - cap} chars truncated]"
    spill_complete = len(text) <= _MAX_EVAL_SPILL_CHARS
    key = f"{kind}-{next(_SPILL_SEQUENCE)}" if spill_complete else None
    if key is not None:
        # Keys come from a process-wide counter, so every store is a fresh entry and
        # dropping the first key evicts the oldest spill a caller can still page back.
        _EVAL_SPILLS[key] = text
        while len(_EVAL_SPILLS) > _MAX_EVAL_SPILLS:
            del _EVAL_SPILLS[next(iter(_EVAL_SPILLS))]
    return echo, True, key, len(text)


def _describe_error(error: BaseException) -> str:
    kind = type(error).__qualname__
    try:
        detail = f"exit status {error.code!r}" if isinstance(error, SystemExit) else str(error)
    except Exception:
        detail = "<message unavailable>"
    return f"{kind}: {detail}" if detail else kind


def _error_location(error: BaseException, code: str) -> dict[str, object] | None:
    """The innermost line of the caller's own code on the error's traceback, or None."""
    lines = [
        lineno
        for frame, lineno in traceback.walk_tb(error.__traceback__)
        if frame.f_code.co_filename == _EVAL_FILENAME
    ]
    if not lines:
        return None
    text = re.split(r"\r\n|\r|\n", code)[lines[-1] - 1].strip()
    return {"line": lines[-1], "text": _truncate(text, _MAX_EVAL_LOCATION_CHARS)}


@mcp.tool(destructive=True)
def rex_eval_python(call: mcp.ToolCall, code: str) -> dict[str, object]:
    """Run Binary Ninja Python; globals: bv, bn, binaryninja, call.

    :param code: Python source; assign to ``result`` to return a value.
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
    error_location: dict[str, object] | None = None
    try:
        with contextlib.redirect_stdout(buffer):
            exec(compile(code, _EVAL_FILENAME, "exec"), namespace)
        if "result" in namespace:
            # repr() inside the try: a raising __repr__ must take the error path below, not
            # escape the handler and drop the captured stdout.
            raw_result = repr(namespace["result"])
    except (Exception, SystemExit, KeyboardInterrupt) as error:
        # Keep failures out of the mcp layer's uncapped str(error) ToolError path.
        error_message = _describe_error(error)
        error_location = _error_location(error, code)

    stdout, stdout_truncated, stdout_key, stdout_length = _spill_echo(
        buffer.getvalue(), _MAX_EVAL_STDOUT_CHARS, "stdout"
    )
    # Success-shaped error field: exactly one of result and error is populated per run.
    result, result_truncated, result_key, result_length = None, False, None, 0
    error, error_truncated = None, False
    if error_message is not None:
        error, error_truncated = _truncate_with_flag(error_message)
    elif raw_result is not None:
        result, result_truncated, result_key, result_length = _spill_echo(
            raw_result, _MAX_EVAL_RESULT_CHARS, "result"
        )
    return {
        "stdout": stdout,
        "stdout_truncated": stdout_truncated,
        "stdout_key": stdout_key,
        "stdout_length": stdout_length,
        "result": result,
        "result_truncated": result_truncated,
        "result_key": result_key,
        "result_length": result_length,
        "error": error,
        "error_truncated": error_truncated,
        "error_location": error_location,
    }


@mcp.tool(read_only=True)
def rex_eval_result(
    call: mcp.ToolCall,
    key: str,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
    limit: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_EVAL_RESULT_PAGE_CHARS)] = 65536,
) -> dict[str, object]:
    """Read a spilled rex_eval_python stdout or result in pages.

    :param key: Spill key reported by rex_eval_python, e.g. ``result-0``.
    :param offset: Characters to skip before the page starts.
    :param limit: Characters returned per page.
    """
    offset = _validate_range("offset", offset, 0)
    limit = _validate_range("limit", limit, 1, _MAX_EVAL_RESULT_PAGE_CHARS)
    text = _EVAL_SPILLS.get(key)
    if text is None:
        raise mcp.ToolError("not_found", f"no spilled eval output under '{_truncate(key)}'")
    page = text[offset : offset + limit]
    more = offset + len(page) < len(text)
    return {
        "key": _truncate(key),
        "value": page,
        "total": len(text),
        "truncated": more,
        "next_offset": offset + len(page) if more else None,
    }


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
