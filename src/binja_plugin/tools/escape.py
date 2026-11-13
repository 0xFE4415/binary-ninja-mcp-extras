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
from typing import Annotated, NamedTuple, TypedDict

import binaryninja
from binaryninja import mcp
from binaryninja.exceptions import RelocationWriteException

from binja_plugin.tools import (
    _functions_needing_update,
    _refresh_analysis,
    _show_nul,
    _truncate,
    _truncate_with_flag,
    _validate_range,
)

_MAX_EVAL_STDOUT_CHARS = 65536
_MAX_EVAL_RESULT_CHARS = 16384
_MAX_EVAL_LOCATION_CHARS = 200
_MAX_EVAL_CHAINED_ERRORS = 8
_EVAL_FILENAME = "<rex_eval_python>"

# Clipped eval echoes spill to process memory (a few recent ones) for rex_eval_result.
_MAX_EVAL_SPILLS = 8
_MAX_EVAL_SPILL_CHARS = 4 * 1024 * 1024
_MAX_EVAL_RESULT_PAGE_CHARS = 65536
_EVAL_SPILLS: OrderedDict[str, str] = OrderedDict()
_SPILL_SEQUENCE = itertools.count()


class _Echo(NamedTuple):
    text: str
    truncated: bool
    spill_key: str | None
    total_length: int


class _ErrorLocation(TypedDict):
    line: int
    text: str


class _EvalPythonResult(TypedDict):
    stdout: str
    stdout_truncated: bool
    stdout_key: str | None
    stdout_length: int
    result: str | None
    result_truncated: bool
    result_key: str | None
    result_length: int
    error: str | None
    error_truncated: bool
    error_location: _ErrorLocation | None


class _EvalPage(TypedDict):
    key: str
    value: str
    total: int
    truncated: bool
    next_offset: int | None


class _MemoryWriteResult(TypedDict):
    address: str
    bytes_written: int
    analysis_complete: bool


def _spill_echo(text: str, cap: int, kind: str) -> _Echo:
    if len(text) <= cap:
        return _Echo(text, False, None, len(text))
    echo = text[:cap] + f"... [{len(text) - cap} chars truncated]"
    spill_complete = len(text) <= _MAX_EVAL_SPILL_CHARS
    key = f"{kind}-{next(_SPILL_SEQUENCE)}" if spill_complete else None
    if key is not None:
        # Keys come from a counter, so the first key is always the oldest spill.
        _EVAL_SPILLS[key] = text
        while len(_EVAL_SPILLS) > _MAX_EVAL_SPILLS:
            del _EVAL_SPILLS[next(iter(_EVAL_SPILLS))]
    return _Echo(echo, True, key, len(text))


def _plain_text(value: object) -> str:
    return str.__str__(value if isinstance(value, str) else str(value))


def _exception_kind(error: BaseException) -> str:
    cls = type(error)
    module = _plain_text(cls.__module__)
    qualname = _plain_text(cls.__qualname__)
    if module in ("builtins", "__main__"):
        return qualname
    return f"{module}.{qualname}"


def _tool_error_detail(error: mcp.ToolError) -> str:
    message = _plain_text(error)
    code = getattr(error, "code", None)
    code_text = _plain_text(code) if isinstance(code, str) else ""
    if not code_text:
        return message
    return f"{code_text}: {message}" if message else code_text


def _exception_detail(error: BaseException) -> str:
    if isinstance(error, SystemExit):
        return f"exit status {error.code!r}"
    if isinstance(error, mcp.ToolError):
        return _tool_error_detail(error)
    return _plain_text(error)


def _describe_one_error(error: BaseException) -> str:
    try:
        kind = _exception_kind(error)
    except Exception:
        kind = "<unknown exception type>"
    try:
        detail = _exception_detail(error)
    except Exception:
        detail = "<message unavailable>"
    return f"{kind}: {detail}" if detail else kind


def _linked_error(error: BaseException) -> tuple[str, BaseException] | None:
    try:
        cause = getattr(error, "__cause__")
        if cause is not None:
            return ("caused by", cause) if isinstance(cause, BaseException) else None
        context = getattr(error, "__context__")
        if context is not None and not error.__suppress_context__:
            return ("while handling", context) if isinstance(context, BaseException) else None
    except Exception:
        return None
    return None


def _unseen_link(error: BaseException, seen: set[int]) -> tuple[str, BaseException] | None:
    link = _linked_error(error)
    if link is None or id(link[1]) in seen:
        return None
    return link


def _describe_error(error: BaseException) -> str:
    description = _describe_one_error(error)
    seen = {id(error)}
    current = error
    for _ in range(_MAX_EVAL_CHAINED_ERRORS):
        link = _unseen_link(current, seen)
        if link is None:
            return description
        relation, current = link
        seen.add(id(current))
        description += f"; {relation} {_describe_one_error(current)}"
    if _unseen_link(current, seen) is not None:
        description += "; ..."
    return description


def _error_location(error: BaseException, code: str) -> _ErrorLocation | None:
    """The innermost line of the caller's own code on the error's traceback, or None."""
    try:
        lines = [
            lineno
            for frame, lineno in traceback.walk_tb(error.__traceback__)
            if frame.f_code.co_filename == _EVAL_FILENAME
        ]
        if not lines:
            return None
        source_lines = re.split(r"\r\n|\r|\n", code)
        # Code the caller compiles under the same filename can report any line, or none.
        if not 1 <= lines[-1] <= len(source_lines):
            return None
        text = source_lines[lines[-1] - 1].strip()
        return {"line": lines[-1], "text": _truncate(text, _MAX_EVAL_LOCATION_CHARS)}
    except Exception:
        return None


@mcp.tool(destructive=True)
def rex_eval_python(call: mcp.ToolCall, code: str) -> _EvalPythonResult:
    """Run Binary Ninja Python; globals: bv, bn, binaryninja, call. Writes; undo skips metadata.

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
    error_location: _ErrorLocation | None = None
    try:
        with contextlib.redirect_stdout(buffer):
            exec(compile(code, _EVAL_FILENAME, "exec"), namespace)
        if "result" in namespace:
            # repr() inside the try: a raising __repr__ takes the error path and keeps the stdout.
            raw_result = repr(namespace["result"])
    except BaseException as error:
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
) -> _EvalPage:
    """Read a spilled rex_eval_python stdout or result in pages.

    :param key: Spill key reported by rex_eval_python, e.g. ``result-0``.
    :param offset: Characters to skip before the page starts.
    :param limit: Characters returned per page.
    """
    offset = _validate_range("offset", offset, 0)
    limit = _validate_range("limit", limit, 1, _MAX_EVAL_RESULT_PAGE_CHARS)
    text = _EVAL_SPILLS.get(key)
    if text is None:
        raise mcp.ToolError(
            "not_found",
            f"no spilled eval output under '{_show_nul(_truncate(key))}'; "
            "keys come from the stdout_key and result_key fields of rex_eval_python",
        )
    page = text[offset : offset + limit]
    more = offset + len(page) < len(text)
    return {
        "key": _truncate(key),
        "value": page,
        "total": len(text),
        "truncated": more,
        "next_offset": offset + len(page) if more else None,
    }


class _ShortWriteError(Exception):
    def __init__(self, written: int) -> None:
        super().__init__(written)
        self.written = written


@mcp.tool(destructive=True)
def rex_memory_write(call: mcp.ToolCall, addr: mcp.Address, hex_data: str) -> _MemoryWriteResult:
    """Overwrite bytes in the binary view with a hex byte string. Writes; undoable.

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
    bv = call.binary_view
    try:
        with bv.undoable_transaction():
            written = bv.write(addr, data)
            if written != len(data):
                raise _ShortWriteError(written)
    except RelocationWriteException:
        raise mcp.ToolError(
            "relocation_overlap",
            f"the {len(data)}-byte range at {hex(addr)} overlaps a relocation; "
            "inspect it with rex_relocation_at",
        ) from None
    except _ShortWriteError as short:
        raise mcp.ToolError(
            "write_failed",
            f"wrote {short.written} of {len(data)} bytes at {hex(addr)}; the address is "
            "probably unmapped or not backed by the file. Nothing was written.",
        ) from None
    analysis_complete = _refresh_analysis(bv, _functions_needing_update(bv))
    return {
        "address": hex(addr),
        "bytes_written": written,
        "analysis_complete": analysis_complete,
    }
