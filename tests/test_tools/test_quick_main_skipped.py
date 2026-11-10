from __future__ import annotations

from typing import Any

import pytest
from helpers import FakeParsingToolCall, get_tool
from helpers_view import (
    SKIP_CAUSES,
    FakeAnalysisSkipReason,
    FakeBinaryView,
    FakeFunction,
    RenderableText,
)

_PENDING_NOTE = (
    "the entry function _start has no HLIL yet; "
    "run bn_analysis_update_and_wait (or rex_analysis_wait with a bound) and retry"
)


def _entry_view(
    *,
    hlil: str | None = None,
    skipped: bool = False,
    reason: FakeAnalysisSkipReason = FakeAnalysisSkipReason.NoSkipReason,
    name: str = "_start",
) -> FakeBinaryView:
    entry = FakeFunction(
        name,
        0x1000,
        0x1100,
        hlil=RenderableText(hlil) if hlil is not None else None,
        analysis_skipped=skipped,
        analysis_skip_reason=reason,
    )
    return FakeBinaryView(entry_point=0x1000, functions=[entry])


def _quick(view: FakeBinaryView) -> dict[str, Any]:
    _, quick = get_tool("rex_quick_main")
    return quick(FakeParsingToolCall(view))


def test_a_pending_entry_keeps_the_wait_advice() -> None:
    result = _quick(_entry_view())
    assert result["method"] == "entry-fallback"
    assert result["main"] is None
    assert result["note"] == _PENDING_NOTE
    assert result["lines"] == []


def test_a_skipped_entry_gets_the_cause_and_no_wait_advice() -> None:
    result = _quick(
        _entry_view(skipped=True, reason=FakeAnalysisSkipReason.ExceedFunctionSizeSkipReason)
    )
    assert result["method"] == "entry-fallback"
    assert result["note"] == (
        "the entry function _start has no HLIL: its analysis is skipped "
        "(it exceeds the analysis.limits.maxFunctionSize limit); "
        "waiting for analysis will not produce one"
    )
    assert result["lines"] == []


@pytest.mark.parametrize("reason", list(FakeAnalysisSkipReason), ids=lambda reason: reason.name)
def test_a_skipped_entry_names_the_core_skip_reason_from_the_shared_map(
    reason: FakeAnalysisSkipReason,
) -> None:
    note = _quick(_entry_view(skipped=True, reason=reason))["note"]
    assert note == (
        f"the entry function _start has no HLIL: its analysis is skipped ({SKIP_CAUSES[reason]}); "
        "waiting for analysis will not produce one"
    )


@pytest.mark.parametrize("reason", list(FakeAnalysisSkipReason), ids=lambda reason: reason.name)
def test_a_skip_reason_without_a_skip_still_means_pending(reason: FakeAnalysisSkipReason) -> None:
    assert _quick(_entry_view(skipped=False, reason=reason))["note"] == _PENDING_NOTE


def test_the_entry_name_in_the_note_is_truncated() -> None:
    note = _quick(_entry_view(name="n" * 600))["note"]
    assert note == (
        f"the entry function {'n' * 512}... [88 chars truncated] has no HLIL yet; "
        "run bn_analysis_update_and_wait (or rex_analysis_wait with a bound) and retry"
    )


def test_a_skipped_entry_that_still_has_hlil_is_read_normally() -> None:
    view = _entry_view(
        hlil="void _start() {\n    __libc_start_main(argc, argv);\n}",
        skipped=True,
        reason=FakeAnalysisSkipReason.AlwaysSkipReason,
    )
    result = _quick(view)
    assert result["note"] == (
        "no main symbol and no parsable __libc_start_main pointer in the entry function"
    )


def test_a_main_symbol_leaves_a_skipped_entry_without_a_note() -> None:
    entry = FakeFunction(
        "_start",
        0x1000,
        0x1100,
        analysis_skipped=True,
        analysis_skip_reason=FakeAnalysisSkipReason.AlwaysSkipReason,
    )
    main = FakeFunction("main", 0x2000, 0x2100, hlil=RenderableText("return 0"))
    view = FakeBinaryView(entry_point=0x1000, functions=[entry, main])
    result = _quick(view)
    assert result["method"] == "symbol"
    assert result["note"] is None
