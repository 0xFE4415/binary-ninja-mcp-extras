"""Analysis-engine progress and view lifecycle tools.

rex_analysis_wait and rex_binary_close manage the view as a running artifact — waiting
out the analysis engine, discarding the view — rather than its analyzed contents.
"""

from __future__ import annotations

import time
from typing import Annotated

from binaryninja import mcp
from binaryninja.binaryview import BinaryView
from binaryninja.enums import AnalysisState

from binja_plugin.tools import _truncate, _validate_range

# rex_analysis_wait: the wait runs on the MCP server thread in ~100 ms slices, so the
# hold is bounded by timeout_ms plus one slice; the in-flight cap bounds the echoed
# hotspot list (per-function analysis time doubles as an analysis profiler).
_MAX_ANALYSIS_WAIT_MS = 600000
_ANALYSIS_WAIT_SLICE_MS = 100
_MAX_ANALYSIS_INFLIGHT = 10


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
