from __future__ import annotations

from typing import Any

import pytest
from helpers import FakeParsingToolCall, _call, get_tool
from helpers_view import FakeBinaryView, FakeFileMetadata, FakeFunction, undo_entry

from binja_plugin import tools


class SteppingClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds * 1000)
        self.now += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> SteppingClock:
    stepping = SteppingClock()
    monkeypatch.setattr("time.sleep", stepping.sleep)
    monkeypatch.setattr("time.monotonic", stepping.monotonic)
    return stepping


def _stale_view(reads: list[bool]) -> tuple[FakeBinaryView, FakeFunction]:
    main = FakeFunction("main", 0x1100, 0x1200)
    main.needs_update_reads = reads
    file = FakeFileMetadata()
    file.undo_entries = [undo_entry("Defined name main")]
    return FakeBinaryView(functions=[main], file=file), main


def _annotate(view: FakeBinaryView) -> Any:
    _, annotate = get_tool("rex_annotate_many")
    return annotate(FakeParsingToolCall(view), [{"addr": 0x1100, "name": "renamed"}])


def _memory_write(view: FakeBinaryView) -> Any:
    _, write = get_tool("rex_memory_write")
    return write(_call(view), 0x1100, "90")


def _undo(view: FakeBinaryView) -> Any:
    _, undo = get_tool("rex_undo")
    return undo(_call(view))


def _redo(view: FakeBinaryView) -> Any:
    view.file.redo_entries = view.file.undo_entries
    view.file.undo_entries = []
    _, redo = get_tool("rex_redo")
    return redo(_call(view))


def _uidf_clear(view: FakeBinaryView) -> Any:
    _, uidf_clear = get_tool("rex_uidf_clear")
    return uidf_clear(_call(view), 0x1100)


_WRITERS = [_annotate, _memory_write, _undo, _redo, _uidf_clear]


@pytest.mark.parametrize("write", _WRITERS, ids=lambda write: write.__name__)
def test_a_write_waits_for_the_functions_it_left_stale(write, clock: SteppingClock) -> None:
    view, _ = _stale_view([True, True, False])
    result = write(view)
    assert view.update_analysis_calls == 1
    assert result["analysis_complete"] is True
    # The scan before the wait reads needs_update too, so the slice count varies by tool.
    assert clock.sleeps
    assert set(clock.sleeps) == {float(tools._ANALYSIS_SLICE_MS)}


@pytest.mark.parametrize("write", _WRITERS, ids=lambda write: write.__name__)
def test_a_write_reports_analysis_incomplete_at_the_deadline(write, clock: SteppingClock) -> None:
    view, _ = _stale_view([True])
    result = write(view)
    assert result["analysis_complete"] is False
    waited = sum(clock.sleeps)
    assert (
        tools._MAX_ANALYSIS_WAIT_MS
        <= waited
        <= tools._MAX_ANALYSIS_WAIT_MS + tools._ANALYSIS_SLICE_MS
    )


@pytest.mark.parametrize("write", _WRITERS, ids=lambda write: write.__name__)
def test_a_write_that_leaves_nothing_stale_returns_without_waiting(
    write, clock: SteppingClock
) -> None:
    view, _ = _stale_view([False])
    result = write(view)
    assert view.update_analysis_calls == 1
    assert result["analysis_complete"] is True
    assert clock.sleeps == []


def test_nothing_applied_or_undone_starts_no_analysis(clock: SteppingClock) -> None:
    view, _ = _stale_view([True])
    _, annotate = get_tool("rex_annotate_many")
    annotate(FakeParsingToolCall(view), [{"addr": 0x9999, "name": "ghost"}])
    view.file.undo_entries = []
    assert _undo(view)["analysis_complete"] is True
    assert view.update_analysis_calls == 0
    assert clock.sleeps == []
