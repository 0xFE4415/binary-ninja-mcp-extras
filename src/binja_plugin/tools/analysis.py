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
    """Triage-style progress snapshot: engine state plus the in-flight analysis hotspots."""
    progress = bv.analysis_progress
    in_flight = sorted(
        bv.analysis_info.active_info, key=lambda entry: entry.analysis_time, reverse=True
    )
    return {
        "progress": {
            # Normalized through AnalysisState() because the API layer hands the state
            # back as the enum in one struct and as a raw int in the other.
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

    :param timeout_ms: Milliseconds to wait; 0 answers a snapshot without waiting.
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
    """Discard this view's unsaved changes and close it."""
    file_metadata = call.binary_view.file
    # The UI adapter keys its discard refusal on this flag; clearing it is the
    # programmatic equivalent of choosing "Discard" in the close prompt.
    file_metadata.modified = False
    try:
        file_metadata.close()
    except Exception as error:
        raise mcp.ToolError("close_failed", f"could not close the view: {error}") from None
    return {"closed": True, "path": _truncate(file_metadata.filename)}
