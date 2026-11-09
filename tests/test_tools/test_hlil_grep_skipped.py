from __future__ import annotations

from helpers import _call, get_tool
from helpers_view import FakeBinaryView, FakeFunction, RenderableText


def _mixed_hlil_view() -> FakeBinaryView:
    hlil_by_name = {
        "a0": RenderableText("call ax\n"),
        "n1": None,
        "b2": RenderableText("nop\n"),
        "n3": None,
        "a4": RenderableText("call ax\n"),
        "a5": RenderableText("call ax\n"),
    }
    functions = [
        FakeFunction(name, 0x1000 + index * 0x10, 0x1010 + index * 0x10, hlil=hlil)
        for index, (name, hlil) in enumerate(hlil_by_name.items())
    ]
    return FakeBinaryView(functions=functions)


def _call_match(name: str, address: int) -> dict[str, object]:
    return {"start": hex(address), "name": name, "lines": ["call ax"]}


def test_hlil_grep_counts_functions_without_hlil_exactly() -> None:
    _, grep = get_tool("rex_hlil_grep")
    assert grep(_call(_mixed_hlil_view()), "call") == {
        "scanned": 4,
        "truncated": False,
        "scan_incomplete": False,
        "skipped_no_hlil": 2,
        "functions": [
            _call_match("a0", 0x1000),
            _call_match("a4", 0x1040),
            _call_match("a5", 0x1050),
        ],
        "next_offset": None,
    }


def test_hlil_grep_reports_zero_skipped_when_every_function_has_hlil() -> None:
    functions = [
        FakeFunction(f"a{index}", 0x1000 + index * 0x10, 0x1010 + index * 0x10, hlil=hlil)
        for index, hlil in enumerate([RenderableText("call ax\n"), RenderableText("nop\n")])
    ]
    _, grep = get_tool("rex_hlil_grep")
    result = grep(_call(FakeBinaryView(functions=functions)), "call")
    assert result["skipped_no_hlil"] == 0
    assert result["scanned"] == 2


def test_hlil_grep_counts_skipped_functions_once_across_pages() -> None:
    view = _mixed_hlil_view()
    _, grep = get_tool("rex_hlil_grep")
    first = grep(_call(view), "call", limit=1)
    assert first == {
        "scanned": 3,
        "truncated": True,
        "scan_incomplete": False,
        "skipped_no_hlil": 2,
        "functions": [_call_match("a0", 0x1000)],
        "next_offset": 4,
    }
    second = grep(_call(view), "call", limit=1, offset=first["next_offset"])
    assert second == {
        "scanned": 2,
        "truncated": True,
        "scan_incomplete": False,
        "skipped_no_hlil": 0,
        "functions": [_call_match("a4", 0x1040)],
        "next_offset": 5,
    }
    third = grep(_call(view), "call", limit=1, offset=second["next_offset"])
    assert third["skipped_no_hlil"] == 0
    assert first["skipped_no_hlil"] + second["skipped_no_hlil"] + third["skipped_no_hlil"] == 2


def test_hlil_grep_counts_only_skipped_functions_at_or_after_offset() -> None:
    view = _mixed_hlil_view()
    _, grep = get_tool("rex_hlil_grep")
    assert grep(_call(view), "call", offset=1)["skipped_no_hlil"] == 2
    assert grep(_call(view), "call", offset=2)["skipped_no_hlil"] == 1
    assert grep(_call(view), "call", offset=4)["skipped_no_hlil"] == 0


def test_hlil_grep_splits_skipped_count_at_the_max_functions_boundary() -> None:
    view = _mixed_hlil_view()
    _, grep = get_tool("rex_hlil_grep")
    first = grep(_call(view), "call", max_functions=2)
    assert first == {
        "scanned": 2,
        "truncated": False,
        "scan_incomplete": True,
        "skipped_no_hlil": 1,
        "functions": [_call_match("a0", 0x1000)],
        "next_offset": 3,
    }
    second = grep(_call(view), "call", max_functions=2, offset=first["next_offset"])
    assert second["skipped_no_hlil"] == 1
    assert second["scanned"] == 2
    assert second["scan_incomplete"] is False
    assert second["next_offset"] is None


def test_hlil_grep_does_not_count_functions_excluded_by_function_filter() -> None:
    view = _mixed_hlil_view()
    _, grep = get_tool("rex_hlil_grep")
    excluded = grep(_call(view), "call", function_filter="^a")
    assert excluded["skipped_no_hlil"] == 0
    assert excluded["scanned"] == 3
    included = grep(_call(view), "call", function_filter="^n")
    assert included == {
        "scanned": 0,
        "truncated": False,
        "scan_incomplete": False,
        "skipped_no_hlil": 2,
        "functions": [],
        "next_offset": None,
    }
    partial = grep(_call(view), "call", function_filter="^(a0|n3)$")
    assert partial["skipped_no_hlil"] == 1
    assert partial["scanned"] == 1
