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


_MAIN_PENDING_NOTE = (
    "the main function main has no HLIL yet; "
    "run bn_analysis_update_and_wait (or rex_analysis_wait with a bound) and retry"
)


def _main_skipped_note(cause: str) -> str:
    return (
        f"the main function main has no HLIL: its analysis is skipped ({cause}); "
        "waiting for analysis will not produce one"
    )


def _view_with_main(main: FakeFunction) -> FakeBinaryView:
    entry = FakeFunction("_start", 0x1000, 0x1100, hlil=RenderableText("void _start() {}"))
    return FakeBinaryView(entry_point=0x1000, functions=[entry, main])


@pytest.mark.parametrize("reason", list(FakeAnalysisSkipReason), ids=lambda reason: reason.name)
def test_a_skipped_main_symbol_names_the_core_skip_reason(
    reason: FakeAnalysisSkipReason,
) -> None:
    main = FakeFunction("main", 0x2000, 0x2100, analysis_skipped=True, analysis_skip_reason=reason)
    result = _quick(_view_with_main(main))
    assert result["method"] == "symbol"
    assert result["main"] == "0x2000"
    assert result["note"] == _main_skipped_note(SKIP_CAUSES[reason])
    assert result["lines"] == []


def test_a_pending_main_symbol_keeps_the_wait_advice() -> None:
    result = _quick(_view_with_main(FakeFunction("main", 0x2000, 0x2100)))
    assert result["method"] == "symbol"
    assert result["note"] == _MAIN_PENDING_NOTE
    assert result["lines"] == []


def test_a_skip_reason_without_a_skip_on_main_still_means_pending() -> None:
    main = FakeFunction(
        "main",
        0x2000,
        0x2100,
        analysis_skip_reason=FakeAnalysisSkipReason.AlwaysSkipReason,
    )
    assert _quick(_view_with_main(main))["note"] == _MAIN_PENDING_NOTE


def test_a_skipped_underscore_main_gets_the_note_with_its_own_name() -> None:
    main = FakeFunction(
        "_main",
        0x2000,
        0x2100,
        analysis_skipped=True,
        analysis_skip_reason=FakeAnalysisSkipReason.AlwaysSkipReason,
    )
    note = _quick(_view_with_main(main))["note"]
    assert note == (
        "the main function _main has no HLIL: its analysis is skipped "
        f"({SKIP_CAUSES[FakeAnalysisSkipReason.AlwaysSkipReason]}); "
        "waiting for analysis will not produce one"
    )


def test_a_skipped_entry_function_named_main_gets_the_main_note() -> None:
    entry = FakeFunction(
        "main",
        0x1000,
        0x1100,
        analysis_skipped=True,
        analysis_skip_reason=FakeAnalysisSkipReason.AlwaysSkipReason,
    )
    result = _quick(FakeBinaryView(entry_point=0x1000, functions=[entry]))
    assert result["method"] == "symbol"
    assert result["note"] == _main_skipped_note(
        SKIP_CAUSES[FakeAnalysisSkipReason.AlwaysSkipReason]
    )


def test_a_skipped_main_found_through_the_entry_pointer_gets_the_note() -> None:
    entry = FakeFunction(
        "_start",
        0x1000,
        0x1100,
        hlil=RenderableText("void _start() {\n    __libc_start_main(0x2000, argc);\n}"),
    )
    target = FakeFunction(
        "sub_2000",
        0x2000,
        0x2100,
        analysis_skipped=True,
        analysis_skip_reason=FakeAnalysisSkipReason.ExceedFunctionSizeSkipReason,
    )
    result = _quick(FakeBinaryView(entry_point=0x1000, functions=[entry, target]))
    assert result["method"] == "entry-arg"
    assert result["main"] == "0x2000"
    assert result["note"] == (
        "the main function sub_2000 has no HLIL: its analysis is skipped "
        f"({SKIP_CAUSES[FakeAnalysisSkipReason.ExceedFunctionSizeSkipReason]}); "
        "waiting for analysis will not produce one"
    )


def test_the_name_of_a_main_found_through_the_entry_pointer_is_truncated_in_the_note() -> None:
    entry = FakeFunction(
        "_start",
        0x1000,
        0x1100,
        hlil=RenderableText("void _start() {\n    __libc_start_main(0x2000, argc);\n}"),
    )
    target = FakeFunction("n" * 600, 0x2000, 0x2100)
    result = _quick(FakeBinaryView(entry_point=0x1000, functions=[entry, target]))
    assert result["note"] == (
        f"the main function {'n' * 512}... [88 chars truncated] has no HLIL yet; "
        "run bn_analysis_update_and_wait (or rex_analysis_wait with a bound) and retry"
    )


def test_a_main_with_hlil_has_no_note_even_when_flagged_skipped() -> None:
    main = FakeFunction(
        "main",
        0x2000,
        0x2100,
        hlil=RenderableText("return 0"),
        analysis_skipped=True,
        analysis_skip_reason=FakeAnalysisSkipReason.AlwaysSkipReason,
    )
    result = _quick(_view_with_main(main))
    assert result["note"] is None
    assert result["lines"] == ["return 0"]
