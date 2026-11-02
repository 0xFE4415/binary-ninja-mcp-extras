"""Unmediated view operations the structured tools do not cover.

rex_eval_python runs trusted code against the Binary Ninja API and rex_memory_write
patches raw bytes: both bypass the abstractions the other tools wrap around the core.
"""

from __future__ import annotations

import contextlib
import io

import binaryninja
from binaryninja import mcp

from binja_plugin.tools import _truncate_with_flag

_MAX_EVAL_STDOUT_CHARS = 65536
_MAX_EVAL_RESULT_CHARS = 16384


@mcp.tool(destructive=True)
def rex_eval_python(call: mcp.ToolCall, code: str) -> dict[str, object]:
    """Run trusted Python against the Binary Ninja API with the active view exposed as bv.

    This is the escape hatch for everything the other tools do not cover. It runs arbitrary
    code with full access to the Binary Ninja API, so it is marked destructive.

    Failures do not raise a tool error: an exception in ``code`` is reported in the
    response's ``error`` field (``error_truncated`` marks clipping) with ``result`` null.
    This is the only tool that answers with a success-shaped error, so protocol-level
    error handling never fires for it — check ``error`` is None instead of relying on
    the call having raised.

    The exec namespace binds the active view as ``bv``, the tool call as ``call``, and
    the ``binaryninja`` module twice: as ``binaryninja`` and under the short alias ``bn``
    for brevity in one-liners.

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
