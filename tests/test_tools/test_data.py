from __future__ import annotations

import pytest
from binaryninja.enums import LowLevelILOperation
from helpers import (
    FakeBinaryView,
    FakeFunction,
    FakeReferenceSource,
    FakeToolError,
    _call,
    get_tool,
)

from binja_plugin import tools


def _caller(name: str, start: int, operation: int) -> FakeReferenceSource:
    return FakeReferenceSource(
        FakeFunction(name, start, start + 0x100),
        start + 0x10,
        arch="x86_64",
        llil_operation=operation,
    )


def _xref_view() -> FakeBinaryView:
    return FakeBinaryView(
        functions=[FakeFunction("main", 0x1100, 0x1200)],
        code_refs={
            0x401000: [
                _caller("reader", 0x2000, LowLevelILOperation.LLIL_LOAD),
                _caller("caller", 0x2100, LowLevelILOperation.LLIL_CALL),
            ]
        },
        data_refs={0x401000: [0x401010, 0x401018]},
    )


def test_xrefs_to_lists_code_and_data_refs() -> None:
    view = _xref_view()
    _, xrefs = get_tool("rex_xrefs_to")
    assert xrefs(_call(view), 0x401000) == {
        "total": 4,
        "truncated": False,
        "code_refs": [
            {
                "function_start": "0x2000",
                "function_name": "reader",
                "arch": "x86_64",
                "address": "0x2010",
                "kind": "code",
            },
            {
                "function_start": "0x2100",
                "function_name": "caller",
                "arch": "x86_64",
                "address": "0x2110",
                "kind": "call",
            },
        ],
        "data_refs": [{"source": "0x401010"}, {"source": "0x401018"}],
    }
    # Pin: both core calls are bounded by exactly the limit cap plus one, so a wider or
    # narrower bound than _MAX_LIMIT + 1 must update this pin deliberately.
    assert view.code_ref_requests == [(0x401000, tools._MAX_LIMIT + 1)]
    assert view.data_ref_requests == [(0x401000, tools._MAX_LIMIT + 1)]


def test_xrefs_to_kinds_pin_tail_calls_as_calls() -> None:
    view = FakeBinaryView(
        code_refs={
            0x401000: [
                _caller("tail", 0x2200, LowLevelILOperation.LLIL_TAILCALL),
                _caller("jump", 0x2300, LowLevelILOperation.LLIL_CALL),
            ]
        }
    )
    _, xrefs = get_tool("rex_xrefs_to")
    kinds = [entry["kind"] for entry in xrefs(_call(view), 0x401000)["code_refs"]]
    assert kinds == ["call", "call"]


def test_xrefs_to_reports_refs_without_a_function_as_code() -> None:
    view = FakeBinaryView(code_refs={0x401000: [FakeReferenceSource(None, 0x9000)]})
    _, xrefs = get_tool("rex_xrefs_to")
    assert xrefs(_call(view), 0x401000)["code_refs"] == [
        {
            "function_start": None,
            "function_name": None,
            "arch": None,
            "address": "0x9000",
            "kind": "code",
        }
    ]


def test_xrefs_to_reports_refs_without_llil_as_code() -> None:
    view = FakeBinaryView(code_refs={0x401000: [FakeReferenceSource(None, 0x9000, arch="x86_64")]})
    _, xrefs = get_tool("rex_xrefs_to")
    entry = xrefs(_call(view), 0x401000)["code_refs"][0]
    assert entry["arch"] == "x86_64"
    assert entry["kind"] == "code"


def test_xrefs_to_empty_is_a_valid_answer() -> None:
    view = FakeBinaryView()
    _, xrefs = get_tool("rex_xrefs_to")
    assert xrefs(_call(view), 0x401000) == {
        "total": 0,
        "truncated": False,
        "code_refs": [],
        "data_refs": [],
    }


def test_xrefs_to_page_crosses_from_code_refs_to_data_refs() -> None:
    view = _xref_view()
    _, xrefs = get_tool("rex_xrefs_to")
    paged = xrefs(_call(view), 0x401000, limit=3, offset=1)
    assert paged == {
        "total": 4,
        "truncated": False,
        "code_refs": [
            {
                "function_start": "0x2100",
                "function_name": "caller",
                "arch": "x86_64",
                "address": "0x2110",
                "kind": "call",
            }
        ],
        "data_refs": [{"source": "0x401010"}, {"source": "0x401018"}],
    }
    assert xrefs(_call(view), 0x401000, limit=1, offset=3) == {
        "total": 4,
        "truncated": False,
        "code_refs": [],
        "data_refs": [{"source": "0x401018"}],
    }


def test_xrefs_to_pagination_beyond_the_result_set() -> None:
    view = _xref_view()
    _, xrefs = get_tool("rex_xrefs_to")
    at_end = xrefs(_call(view), 0x401000, limit=10, offset=4)
    assert at_end == {"total": 4, "truncated": False, "code_refs": [], "data_refs": []}
    past_end = xrefs(_call(view), 0x401000, limit=10, offset=10**9)
    assert past_end == {"total": 4, "truncated": False, "code_refs": [], "data_refs": []}
    # limit=0 pages nothing out; the scan stops at the first match past the empty window,
    # so "total" caps at offset+limit+1 and truncated says a further match existed.
    zero = xrefs(_call(view), 0x401000, limit=0)
    assert zero == {"total": 1, "truncated": True, "code_refs": [], "data_refs": []}


def test_xrefs_to_sorts_each_kind_by_address() -> None:
    view = FakeBinaryView(
        code_refs={
            0x401000: [
                FakeReferenceSource(None, 0x9000),
                FakeReferenceSource(None, 0x6000),
            ]
        },
        data_refs={0x401000: [0x401020, 0x401018]},
    )
    _, xrefs = get_tool("rex_xrefs_to")
    result = xrefs(_call(view), 0x401000)
    assert [entry["address"] for entry in result["code_refs"]] == ["0x6000", "0x9000"]
    assert [entry["source"] for entry in result["data_refs"]] == ["0x401018", "0x401020"]


def test_xrefs_to_defaults_to_a_bounded_page() -> None:
    view = FakeBinaryView(
        code_refs={
            0x401000: [
                FakeReferenceSource(None, 0x8000 + index) for index in range(tools._MAX_LIMIT + 5)
            ]
        }
    )
    _, xrefs = get_tool("rex_xrefs_to")
    result = xrefs(_call(view), 0x401000)
    assert len(result["code_refs"]) == 100
    assert result["data_refs"] == []
    assert result["truncated"] is True
    # Like the other sweep tools, total counts only what was seen: exact when the page
    # is not truncated, otherwise the first item past the window.
    assert result["total"] == 101
    complete = xrefs(_call(view), 0x401000, limit=tools._MAX_LIMIT)
    assert len(complete["code_refs"]) == tools._MAX_LIMIT
    assert complete["total"] == tools._MAX_LIMIT + 1
    assert complete["truncated"] is True


def test_xrefs_to_truncates_long_function_names() -> None:
    view = FakeBinaryView(
        code_refs={
            0x401000: [
                _caller("long" * 200, 0x2000, LowLevelILOperation.LLIL_CALL),
            ]
        }
    )
    _, xrefs = get_tool("rex_xrefs_to")
    name = xrefs(_call(view), 0x401000)["code_refs"][0]["function_name"]
    assert name == "long" * 128 + f"... [{800 - tools._MAX_CHARS} chars truncated]"


def test_xrefs_to_rejects_out_of_range_windows() -> None:
    view = FakeBinaryView(data_refs={0x401000: [0x401010]})
    _, xrefs = get_tool("rex_xrefs_to")
    for kwargs, message in (
        ({"limit": -1}, "Invalid integer parameter 'limit': Must be at least 0"),
        (
            {"limit": tools._MAX_LIMIT + 1},
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}",
        ),
        ({"offset": -1}, "Invalid integer parameter 'offset': Must be at least 0"),
    ):
        with pytest.raises(FakeToolError) as exc:
            xrefs(_call(view), 0x401000, **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    assert xrefs(_call(view), 0x401000, limit=tools._MAX_LIMIT)["total"] == 1
