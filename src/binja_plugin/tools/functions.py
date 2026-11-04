"""Function-object tools: containment lookups, defining and undefining, call-graph paths."""

from __future__ import annotations

import time
from collections import deque
from typing import Annotated, Literal

from binaryninja import mcp
from binaryninja.function import Function

from binja_plugin.tools import (
    _function_entry,
    _parse_address_batch,
    _require_function,
    _validate_range,
)

_MAX_CALL_PATH_DEPTH = 16
_MAX_CALL_PATHS = 50
_MAX_FUNCTION_ENTRIES = 50
_MAX_DEFINE_BATCH = 100

# The define tools' analysis wait polls in ~100 ms slices like rex_analysis_wait; a
# defined function counts as analyzed once the engine has produced its first basic
# block, which is the same gate the decompile and disassembly tools go through.
_DEFINE_WAIT_SLICE_MS = 100
_MAX_DEFINE_WAIT_MS = 600000


def _is_analyzed(function: Function) -> bool:
    return len(list(function.basic_blocks)) > 0


def _settle_analysis(
    functions: list[Function], wait: bool, timeout_ms: int
) -> tuple[list[Function], int]:
    """Return the functions still without a basic block and the elapsed wall time.

    With ``wait`` set, the unanalyzed functions are polled in ~100 ms slices until every
    one has a block or the deadline passes; without it the state is sampled once.
    """
    if not wait:
        return [function for function in functions if not _is_analyzed(function)], 0
    started = time.monotonic()
    deadline = started + timeout_ms / 1000
    pending = [function for function in functions if not _is_analyzed(function)]
    while pending and time.monotonic() < deadline:
        time.sleep(_DEFINE_WAIT_SLICE_MS / 1000)
        pending = [function for function in functions if not _is_analyzed(function)]
    return pending, round((time.monotonic() - started) * 1000)


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
    :param direction: "callers" walks the edges reaching the target, "callees" the edges leaving.
    :param max_depth: Maximum edges walked from the starting function.
    :param max_paths: Maximum paths returned.
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


@mcp.tool(destructive=True)
def rex_function_define(
    call: mcp.ToolCall,
    start: mcp.Address,
    wait: bool = True,
    timeout_ms: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DEFINE_WAIT_MS)] = 10000,
) -> dict[str, object]:
    """Turn the bytes at an address into a function, optionally waiting for analysis.

    :param start: Address of the new function's entry point.
    :param wait: Poll until the function has at least one basic block.
    :param timeout_ms: Bound on the analysis wait when ``wait`` is set.
    """
    timeout_ms = _validate_range("timeout_ms", timeout_ms, 0, _MAX_DEFINE_WAIT_MS)
    function = call.binary_view.create_user_function(start)
    if function is None:
        raise mcp.ToolError("define_failed", f"could not create a function at {start:#x}")
    pending, waited_ms = _settle_analysis([function], wait, timeout_ms)
    return {**_function_entry(function), "analyzed": not pending, "waited_ms": waited_ms}


@mcp.tool(destructive=True)
def rex_function_define_many(
    call: mcp.ToolCall,
    addresses: list[str],
    wait: bool = True,
    timeout_ms: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DEFINE_WAIT_MS)] = 10000,
) -> dict[str, object]:
    """Turn the bytes at many addresses into functions, then optionally wait for analysis.

    :param addresses: 1 to 100 address expressions; the batch fails whole on a bad entry.
    :param wait: Poll until every defined function has at least one basic block.
    :param timeout_ms: Bound on the analysis wait when ``wait`` is set.
    """
    timeout_ms = _validate_range("timeout_ms", timeout_ms, 0, _MAX_DEFINE_WAIT_MS)
    parsed = _parse_address_batch(call, addresses, _MAX_DEFINE_BATCH, "addresses")
    defined: list[Function] = []
    failed: list[str] = []
    for address in parsed:
        function = call.binary_view.create_user_function(address)
        if function is None:
            failed.append(hex(address))
        else:
            defined.append(function)
    pending, waited_ms = _settle_analysis(defined, wait, timeout_ms)
    still_pending = {function.start for function in pending}
    return {
        "defined": [
            {**_function_entry(function), "analyzed": function.start not in still_pending}
            for function in defined
        ],
        "failed": failed,
        "pending": [hex(function.start) for function in pending],
        "waited_ms": waited_ms,
    }


@mcp.tool(destructive=True)
def rex_function_undefine(call: mcp.ToolCall, start: mcp.Address) -> dict[str, object]:
    """Remove the user function covering an address.

    :param start: Any address inside the function to remove.
    """
    function = _require_function(call.binary_view, start)
    call.binary_view.remove_user_function(function)
    return _function_entry(function)
