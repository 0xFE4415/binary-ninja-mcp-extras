from __future__ import annotations

import pytest
from helpers import (
    FakeToolError,
    _call,
    get_tool,
)
from helpers_view import (
    FakeActiveAnalysisInfo,
    FakeAnalysisInfo,
    FakeAnalysisProgress,
    FakeAnalysisState,
    FakeBinaryView,
    FakeFileMetadata,
    FakeFunction,
)

from binja_plugin import tools
from binja_plugin.tools import analysis


class FakeClock:
    """Deterministic clock for the rex_analysis_wait loop: sleep advances the clock."""

    def __init__(self) -> None:
        self.now_ms = 0
        self.sleeps: list[int] = []

    def monotonic(self) -> float:
        return self.now_ms / 1000

    def sleep(self, seconds: float) -> None:
        slept_ms = round(seconds * 1000)
        self.sleeps.append(slept_ms)
        self.now_ms += slept_ms


def _patch_time(monkeypatch: pytest.MonkeyPatch, clock: FakeClock) -> None:
    monkeypatch.setattr("time.sleep", clock.sleep)
    monkeypatch.setattr("time.monotonic", clock.monotonic)


def _running_progress(count: int = 3, total: int = 10) -> list[FakeAnalysisProgress]:
    return [FakeAnalysisProgress(FakeAnalysisState.AnalyzeState, count, total)]


def test_analysis_wait_returns_immediately_when_analysis_is_idle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    _patch_time(monkeypatch, clock)
    view = FakeBinaryView(functions=[FakeFunction("f", 0x1000, 0x1010)])
    _, wait = get_tool("rex_analysis_wait")
    assert wait(_call(view), timeout_ms=600000) == {
        "completed": True,
        "elapsed_ms": 0,
        "progress": {"state": "IdleState", "count": 0, "total": 0},
        "function_count": 1,
        "in_flight": [],
        "truncated": False,
    }
    # Already idle: the snapshot is answered without a single sleep.
    assert clock.sleeps == []


def test_analysis_wait_sleeps_until_analysis_completes(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = FakeClock()
    _patch_time(monkeypatch, clock)
    view = FakeBinaryView(
        analysis_progress_sequence=[
            *_running_progress(3, 10),
            *_running_progress(7, 10),
            FakeAnalysisProgress(FakeAnalysisState.IdleState, 10, 10),
        ],
        functions=[FakeFunction("a", 0x1000, 0x1010), FakeFunction("b", 0x2000, 0x2010)],
    )
    _, wait = get_tool("rex_analysis_wait")
    result = wait(_call(view), timeout_ms=60000)
    assert result["completed"] is True
    assert result["elapsed_ms"] == 200
    assert result["progress"] == {"state": "IdleState", "count": 10, "total": 10}
    assert clock.sleeps == [100, 100]


def test_analysis_wait_stops_at_the_deadline_and_snapshots(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = FakeClock()
    _patch_time(monkeypatch, clock)
    view = FakeBinaryView(analysis_progress_sequence=_running_progress(1, 10))
    _, wait = get_tool("rex_analysis_wait")
    result = wait(_call(view), timeout_ms=350)
    # The server hold is bounded by timeout_ms plus one slice: 350 ms of budget, four
    # 100 ms slices because the deadline check happens between slices.
    assert result == {
        "completed": False,
        "elapsed_ms": 400,
        "progress": {"state": "AnalyzeState", "count": 1, "total": 10},
        "function_count": 0,
        "in_flight": [],
        "truncated": False,
    }
    assert clock.sleeps == [100, 100, 100, 100]


def test_analysis_wait_zero_timeout_snapshots_without_sleeping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    _patch_time(monkeypatch, clock)
    view = FakeBinaryView(analysis_progress_sequence=_running_progress())
    _, wait = get_tool("rex_analysis_wait")
    result = wait(_call(view), timeout_ms=0)
    assert result["completed"] is False
    assert result["elapsed_ms"] == 0
    assert result["progress"] == {"state": "AnalyzeState", "count": 3, "total": 10}
    assert clock.sleeps == []


def test_analysis_wait_rejects_out_of_range_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = FakeClock()
    _patch_time(monkeypatch, clock)
    _, wait = get_tool("rex_analysis_wait")
    for value, requirement in (
        (-1, "at least 0"),
        (analysis._MAX_ANALYSIS_WAIT_MS + 1, f"at most {analysis._MAX_ANALYSIS_WAIT_MS}"),
    ):
        message = f"Invalid integer parameter 'timeout_ms': Must be {requirement}"
        with pytest.raises(FakeToolError) as exc:
            wait(_call(FakeBinaryView()), timeout_ms=value)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # The range bounds themselves are accepted, not normalized.
    wait(_call(FakeBinaryView()), timeout_ms=0)
    wait(_call(FakeBinaryView()), timeout_ms=analysis._MAX_ANALYSIS_WAIT_MS)
    assert clock.sleeps == []


def test_analysis_wait_reports_in_flight_functions_most_expensive_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    _patch_time(monkeypatch, clock)
    view = FakeBinaryView(
        analysis_info=FakeAnalysisInfo(
            FakeAnalysisState.AnalyzeState,
            18940,
            [
                FakeActiveAnalysisInfo(FakeFunction("fast", 0x2000, 0x2100), 40),
                FakeActiveAnalysisInfo(FakeFunction("slow", 0x1000, 0x1100), 18900),
                FakeActiveAnalysisInfo(FakeFunction("n" * 600, 0x3000, 0x3100), 5),
            ],
        )
    )
    _, wait = get_tool("rex_analysis_wait")
    result = wait(_call(view), timeout_ms=0)
    # Sorted by per-function analysis time, the debrief's hotspot profiler, and long
    # names go through the same echo cap as every other tool.
    assert result["in_flight"] == [
        {"start": "0x1000", "name": "slow", "analysis_time_ms": 18900},
        {"start": "0x2000", "name": "fast", "analysis_time_ms": 40},
        {
            "start": "0x3000",
            "name": "n" * tools._MAX_CHARS + "... [88 chars truncated]",
            "analysis_time_ms": 5,
        },
    ]
    assert result["truncated"] is False


def test_analysis_wait_caps_the_in_flight_list(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = FakeClock()
    _patch_time(monkeypatch, clock)
    active = [
        FakeActiveAnalysisInfo(
            FakeFunction(f"f{i:02d}", 0x1000 + 0x10 * i, 0x1010 + 0x10 * i), analysis_time=100 - i
        )
        for i in range(analysis._MAX_ANALYSIS_INFLIGHT + 1)
    ]
    view = FakeBinaryView(
        analysis_info=FakeAnalysisInfo(FakeAnalysisState.AnalyzeState, 60, active)
    )
    _, wait = get_tool("rex_analysis_wait")
    result = wait(_call(view), timeout_ms=0)
    assert result["truncated"] is True
    assert len(result["in_flight"]) == analysis._MAX_ANALYSIS_INFLIGHT
    # The cap keeps the most expensive functions, in cost order.
    assert [entry["name"] for entry in result["in_flight"]] == [
        f"f{i:02d}" for i in range(analysis._MAX_ANALYSIS_INFLIGHT)
    ]
    # Exactly at the cap nothing was dropped, so the flag stays false.
    at_cap = FakeBinaryView(
        analysis_info=FakeAnalysisInfo(FakeAnalysisState.AnalyzeState, 60, active[:-1])
    )
    assert wait(_call(at_cap), timeout_ms=0)["truncated"] is False


def test_binary_close_discards_and_closes() -> None:
    file_metadata = FakeFileMetadata(filename="/tmp/probe")
    view = FakeBinaryView(file=file_metadata)
    file_metadata.modified = True
    _, close = get_tool("rex_binary_close")
    assert close(_call(view)) == {"closed": True, "path": "/tmp/probe"}
    # The modified flag is cleared first (the BNMarkFileSaved path) and the file is
    # closed through the core: nothing is written, nothing survives the call.
    assert file_metadata.saved_marks == 1
    assert file_metadata.closed is True


def test_binary_close_reports_close_failures() -> None:
    file_metadata = FakeFileMetadata(filename="/tmp/probe")
    file_metadata.close_error = OSError("wedged")
    view = FakeBinaryView(file=file_metadata)
    _, close = get_tool("rex_binary_close")
    with pytest.raises(FakeToolError) as exc:
        close(_call(view))
    assert exc.value.code == "close_failed"
    assert "wedged" in exc.value.message


def test_binary_close_failure_restores_modified_flag() -> None:
    file_metadata = FakeFileMetadata(filename="/tmp/probe")
    file_metadata.modified = True
    file_metadata.close_error = OSError("wedged")
    view = FakeBinaryView(file=file_metadata)
    _, close = get_tool("rex_binary_close")
    with pytest.raises(FakeToolError):
        close(_call(view))
    assert file_metadata.modified is True


def test_binary_close_failure_keeps_unmodified_flag_false() -> None:
    file_metadata = FakeFileMetadata(filename="/tmp/probe")
    file_metadata.close_error = OSError("wedged")
    view = FakeBinaryView(file=file_metadata)
    _, close = get_tool("rex_binary_close")
    with pytest.raises(FakeToolError):
        close(_call(view))
    assert file_metadata.modified is False
