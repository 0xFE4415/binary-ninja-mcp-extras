from __future__ import annotations

import pytest
from helpers import (
    FakeToolError,
    _call,
    _view_with_functions,
    get_tool,
)
from helpers_view import (
    FakeBinaryView,
    FakeFunction,
    FakeSegment,
    SpyBinaryView,
)

from binja_plugin import tools
from binja_plugin.tools import scanning


def test_data_find_finds_pattern_and_wildcards() -> None:
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 0x10)],
        memory={0x1000: b"\x90\x48\x8b\x05\x48\x8b\x05"},
    )
    _, find = get_tool("rex_data_find")
    result = find(_call(view), pattern="48 8b 05")
    assert result["matches"] == ["0x1001", "0x1004"]
    assert result["total"] == 2
    assert find(_call(view), pattern="48 ?? 05")["matches"] == ["0x1001", "0x1004"]


def test_data_find_reports_overlapping_matches() -> None:
    view = FakeBinaryView(segments=[FakeSegment(0x1000, 4)], memory={0x1000: b"\x90\x90\x90\x90"})
    _, find = get_tool("rex_data_find")
    result = find(_call(view), pattern="9090")
    assert result["matches"] == ["0x1000", "0x1001", "0x1002"]
    assert result["total"] == 3


def test_data_find_advances_through_each_chunk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "_READ_CHUNK", 4)
    view = SpyBinaryView(
        segments=[FakeSegment(0x1000, 12)],
        memory={0x1000: b"\xeb\x90" * 6},
    )
    _, find = get_tool("rex_data_find")
    assert find(_call(view), pattern="eb") == {
        "total": 6,
        "truncated": False,
        "matches": ["0x1000", "0x1002", "0x1004", "0x1006", "0x1008", "0x100a"],
    }
    assert view.read_addresses == [0x1000, 0x1004, 0x1008]


def test_data_find_finds_matches_across_chunk_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "_READ_CHUNK", 4)
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x33\xeb\x00\x00\x33\xeb"},
    )
    _, find = get_tool("rex_data_find")
    result = find(_call(view), pattern="33 eb")
    assert result["total"] == 2
    assert result["matches"] == ["0x1002", "0x1006"]


def test_data_find_matches_straddling_chunk_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "_READ_CHUNK", 4)
    _, find = get_tool("rex_data_find")
    # A match straddling the chunk edge is only visible because each read extends
    # pattern_length - 1 bytes past the chunk; dropping that overlap must fail this test.
    straddle = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x00\x33\xeb\x00\x00\x00"},
    )
    assert find(_call(straddle), pattern="33 eb") == {
        "total": 1,
        "truncated": False,
        "matches": ["0x1003"],
    }
    # A match starting exactly at the chunk edge is reported once: the reads overlap, but
    # every match start belongs to exactly one read.
    boundary = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x00\x00\x33\xeb\x00\x00"},
    )
    assert find(_call(boundary), pattern="33 eb") == {
        "total": 1,
        "truncated": False,
        "matches": ["0x1004"],
    }


def test_data_find_finds_matches_after_chunk_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "_READ_CHUNK", 4)
    view = FakeBinaryView(
        segments=[FakeSegment(0x2000, 8)],
        memory={0x2000: b"\x00\x00\x00\x00\x00\x33\xeb\x00"},
    )
    _, find = get_tool("rex_data_find")
    assert find(_call(view), pattern="33 eb")["matches"] == ["0x2005"]


def test_data_find_section_limit_and_errors() -> None:
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 0x100), FakeSegment(0x9000, 0x10)],
        memory={0x1000: b"\xeb\x0e" * 4, 0x9000: b"\xeb\x0e"},
        sections={"text": (0x1002, 0x1006)},
    )
    _, find = get_tool("rex_data_find")
    # The section starts and ends inside the first segment, so both bounds are clamped:
    # matches at 0x1000 (before the section) and 0x1006 (past it) must be excluded.
    sectioned = find(_call(view), pattern="eb0e", section="text")
    assert sectioned["matches"] == ["0x1002", "0x1004"]
    assert sectioned["total"] == 2
    paged = find(_call(view), pattern="eb0e", limit=1, offset=1)
    # The scan stops at the first match past the window, so "total" caps at
    # offset+limit+1 == 3 even though 5 matches exist.
    assert paged["total"] == 3
    assert paged["matches"] == ["0x1002"]
    assert paged["truncated"] is True
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern="zz")
    assert exc.value.code == "invalid_pattern"
    # The message is the underlying HexPatternError's text, passed through str().
    assert exc.value.message == "invalid hex byte token 'zz'"


@pytest.mark.parametrize("tool_name", ["rex_data_find", "rex_find_functions_by_pattern"])
@pytest.mark.parametrize("pattern", ["+f", "-1", "\u0664\u0668", "0x"])
def test_pattern_tools_report_invalid_pattern_for_lenient_int_forms(
    tool_name: str, pattern: str
) -> None:
    view = FakeBinaryView(segments=[FakeSegment(0x1000, 4)], memory={0x1000: b"\x0f\x0f\x0f\x0f"})
    _, tool = get_tool(tool_name)
    with pytest.raises(FakeToolError) as exc:
        tool(_call(view), pattern=pattern)
    assert exc.value.code == "invalid_pattern"
    assert exc.value.message == f"invalid hex byte token '{pattern}'"


def test_data_find_pagination_beyond_the_result_set() -> None:
    view = FakeBinaryView(segments=[FakeSegment(0x1000, 8)], memory={0x1000: b"\x90" * 8})
    _, find = get_tool("rex_data_find")
    at_end = find(_call(view), pattern="90", limit=10, offset=8)
    assert at_end == {"total": 8, "truncated": False, "matches": []}
    past_end = find(_call(view), pattern="90", limit=10, offset=10**9)
    assert past_end == {"total": 8, "truncated": False, "matches": []}
    # limit=0: the scan stops at the first match past the empty window, so "total"
    # caps at offset+limit+1 while truncated reports that a further match existed.
    zero = find(_call(view), pattern="90", limit=0)
    assert zero == {"total": 1, "truncated": True, "matches": []}


def test_data_find_caps_limit() -> None:
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 600)],
        memory={0x1000: b"\x90" * 600},
    )
    _, find = get_tool("rex_data_find")
    # Exactly at the cap the limit is honored; the scan stops one match past the window.
    result = find(_call(view), pattern="90", limit=tools._MAX_LIMIT)
    assert len(result["matches"]) == tools._MAX_LIMIT
    assert result["total"] == tools._MAX_LIMIT + 1
    assert result["truncated"] is True
    # Past the cap the request is rejected, not silently normalized.
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern="90", limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )


def test_data_find_skips_unreadable_segments() -> None:
    view = FakeBinaryView(segments=[FakeSegment(0x9000, 0x10)])
    _, find = get_tool("rex_data_find")
    assert find(_call(view), pattern="ff")["total"] == 0


def test_data_find_skips_segments_marked_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "_READ_CHUNK", 4)
    # The segment flag says unreadable even though bytes answer reads there: the scan
    # must skip the segment up front instead of relying on short-read recovery — and
    # must keep scanning the segments after it (a break there would lose 0x2000).
    skipped = SpyBinaryView(
        segments=[FakeSegment(0x1000, 8, readable=False), FakeSegment(0x2000, 8)],
        memory={0x1000: b"\xeb\x0e" * 4, 0x2000: b"\xeb\x0e\x90\x90\x90\x90\x90\x90"},
    )
    _, find = get_tool("rex_data_find")
    assert find(_call(skipped), pattern="eb0e")["total"] == 1
    assert skipped.read_addresses == [0x2000, 0x2004]
    # Both scan tools go through the same segment walk: rex_find_functions_by_pattern
    # must skip the unreadable segment too.
    functioned = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8, readable=False), FakeSegment(0x2000, 8)],
        memory={0x1000: b"\xeb\x0e" * 4, 0x2000: b"\xeb\x0e\x90\x90\x90\x90\x90\x90"},
        functions=[FakeFunction("f", 0x2000, 0x2100)],
    )
    _, by_function = get_tool("rex_find_functions_by_pattern")
    assert by_function(_call(functioned), "eb0e") == {
        "total": 1,
        "truncated": False,
        "functions": [
            {
                "start": "0x2000",
                "name": "f",
                "match_count": 1,
                "addresses": ["0x2000"],
                "addresses_truncated": False,
            }
        ],
    }


def test_data_find_reports_an_invalid_pattern_before_a_missing_section() -> None:
    _, find = get_tool("rex_data_find")
    with pytest.raises(FakeToolError) as exc:
        find(_call(FakeBinaryView()), pattern="zz", section="nope")
    assert exc.value.code == "invalid_pattern"


def _holes_view() -> SpyBinaryView:
    return SpyBinaryView(
        segments=[
            FakeSegment(0x800, 0x10),  # wholly unreadable
            FakeSegment(0x1000, 0x20),  # readable only from its third chunk on
            FakeSegment(0x2000, 0x10),
        ],
        memory={
            0x1010: b"\x00\x00\x00\x00\xeb\x0e\x00\x00",
            0x2000: b"\x00\x00\x00\x00\xeb\x0e\x00\x00",
        },
        sections={"gap": (0x5000, 0x5010), "second": (0x2002, 0x2010)},
    )


def test_data_find_recovers_matches_after_unreadable_holes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tools, "_READ_CHUNK", 8)
    _, find = get_tool("rex_data_find")
    # Empty reads skip a chunk, not the rest of the segment or the remaining segments.
    assert find(_call(_holes_view()), pattern="eb0e")["matches"] == ["0x1014", "0x2004"]


def test_data_find_section_outside_every_segment_reads_nothing() -> None:
    view = _holes_view()
    _, find = get_tool("rex_data_find")
    assert find(_call(view), pattern="eb0e", section="gap") == {
        "total": 0,
        "truncated": False,
        "matches": [],
    }
    assert view.read_addresses == []
    assert find(_call(view), pattern="eb0e", section="second")["matches"] == ["0x2004"]


def _constant_view() -> FakeBinaryView:
    functions = [
        FakeFunction("main", 0x1100, 0x1200),
        FakeFunction("handler", 0x2000, 0x2100),
        FakeFunction("sink", 0x3000, 0x3100),
    ]
    return FakeBinaryView(
        functions=functions,
        constant_references=[
            (0x31337, 0x1140, functions[0]),
            (0x31337, 0x1150, functions[0]),
            (0x31337, 0x2050, functions[1]),
            (0x1234, 0x3010, functions[2]),
        ],
    )


def test_constant_find_reports_functions_from_the_constant_search() -> None:
    view = _constant_view()
    _, find = get_tool("rex_constant_find")
    result = find(_call(view), value=0x31337)
    assert result == {
        "total": 2,
        "truncated": False,
        "functions": [
            {
                "start": "0x1100",
                "name": "main",
                "addresses": ["0x1140", "0x1150"],
                "addresses_truncated": False,
            },
            {
                "start": "0x2000",
                "name": "handler",
                "addresses": ["0x2050"],
                "addresses_truncated": False,
            },
        ],
    }
    assert find(_call(view), value=0x1234)["functions"][0]["addresses"] == ["0x3010"]


def test_constant_find_skips_lines_outside_functions() -> None:
    view = _constant_view()
    view.constant_references.append((7, 0x9000, None))
    _, find = get_tool("rex_constant_find")
    assert find(_call(view), value=7) == {"total": 0, "truncated": False, "functions": []}


def test_constant_find_caps_matches_per_function() -> None:
    function = FakeFunction("sink", 0x3000, 0x3100)
    view = FakeBinaryView(
        functions=[function],
        constant_references=[(7, 0x3000 + index, function) for index in range(8)],
    )
    _, find = get_tool("rex_constant_find")
    result = find(_call(view), value=7)
    assert result == {
        "total": 1,
        "truncated": False,
        "functions": [
            {
                "start": "0x3000",
                "name": "sink",
                "addresses": [hex(0x3000 + index) for index in range(6)],
                "addresses_truncated": True,
            }
        ],
    }
    # Exactly at the cap the list is whole, so the flag stays false and the echo
    # distinguishes six real references from a clipped longer one.
    exact = FakeFunction("main", 0x1000, 0x1100)
    six_view = FakeBinaryView(
        functions=[exact],
        constant_references=[(7, 0x1000 + index, exact) for index in range(6)],
    )
    assert find(_call(six_view), value=7) == {
        "total": 1,
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "main",
                "addresses": [hex(0x1000 + index) for index in range(6)],
                "addresses_truncated": False,
            }
        ],
    }


def test_constant_find_lists_a_repeated_address_once() -> None:
    function = FakeFunction("sub_413406", 0x413406, 0x413500)
    view = FakeBinaryView(
        functions=[function],
        constant_references=[(0, 0x413406, function)] * 7,
        start=0x400000,
        end=0x426950,
    )
    _, find = get_tool("rex_constant_find")
    assert find(_call(view), value=0) == {
        "total": 1,
        "truncated": False,
        "functions": [
            {
                "start": "0x413406",
                "name": "sub_413406",
                "addresses": ["0x413406"],
                "addresses_truncated": False,
            }
        ],
    }


def test_constant_find_keeps_the_first_occurrence_order_of_repeated_addresses() -> None:
    function = FakeFunction("sink", 0x3000, 0x3100)
    view = FakeBinaryView(
        functions=[function],
        constant_references=[
            (7, address, function) for address in (0x3008, 0x3000, 0x3008, 0x3004, 0x3000, 0x3004)
        ],
    )
    _, find = get_tool("rex_constant_find")
    assert find(_call(view), value=7)["functions"][0]["addresses"] == ["0x3008", "0x3000", "0x3004"]


@pytest.mark.parametrize(
    ("distinct", "repeats", "expected_count", "expected_truncated"),
    [
        (5, 1, 5, False),
        (5, 3, 5, False),
        (6, 1, 6, False),
        (6, 2, 6, False),
        (6, 4, 6, False),
        (7, 1, 6, True),
        (7, 2, 6, True),
        (7, 4, 6, True),
    ],
)
def test_constant_find_caps_distinct_addresses_not_hits(
    distinct: int, repeats: int, expected_count: int, expected_truncated: bool
) -> None:
    function = FakeFunction("sink", 0x3000, 0x3100)
    view = FakeBinaryView(
        functions=[function],
        constant_references=[
            (7, 0x3000 + index, function) for index in range(distinct) for _ in range(repeats)
        ],
    )
    _, find = get_tool("rex_constant_find")
    entry = find(_call(view), value=7)["functions"][0]
    assert entry["addresses"] == [hex(0x3000 + index) for index in range(expected_count)]
    assert entry["addresses_truncated"] is expected_truncated


def test_constant_find_repeats_after_the_cap_do_not_truncate() -> None:
    function = FakeFunction("sink", 0x3000, 0x3100)
    view = FakeBinaryView(
        functions=[function],
        constant_references=[(7, 0x3000 + index, function) for index in range(6)]
        + [(7, 0x3000, function), (7, 0x3005, function), (7, 0x3003, function)],
    )
    _, find = get_tool("rex_constant_find")
    entry = find(_call(view), value=7)["functions"][0]
    assert entry["addresses"] == [hex(0x3000 + index) for index in range(6)]
    assert entry["addresses_truncated"] is False


def test_constant_find_truncates_on_a_new_address_after_repeats_at_the_cap() -> None:
    function = FakeFunction("sink", 0x3000, 0x3100)
    view = FakeBinaryView(
        functions=[function],
        constant_references=[(7, 0x3000 + index, function) for index in range(6)]
        + [(7, 0x3000, function), (7, 0x3006, function), (7, 0x3006, function)],
    )
    _, find = get_tool("rex_constant_find")
    entry = find(_call(view), value=7)["functions"][0]
    assert entry["addresses"] == [hex(0x3000 + index) for index in range(6)]
    assert entry["addresses_truncated"] is True


def test_constant_find_counts_and_pages_functions_not_repeated_hits() -> None:
    first = FakeFunction("first", 0x1000, 0x1100)
    second = FakeFunction("second", 0x2000, 0x2100)
    view = FakeBinaryView(
        functions=[first, second],
        constant_references=[(7, 0x1000, first)] * 9 + [(7, 0x2000, second)] * 9,
    )
    _, find = get_tool("rex_constant_find")
    assert find(_call(view), value=7, limit=1) == {
        "total": 2,
        "truncated": True,
        "functions": [
            {
                "start": "0x1000",
                "name": "first",
                "addresses": ["0x1000"],
                "addresses_truncated": False,
            }
        ],
    }
    assert find(_call(view), value=7, limit=1, offset=1) == {
        "total": 2,
        "truncated": False,
        "functions": [
            {
                "start": "0x2000",
                "name": "second",
                "addresses": ["0x2000"],
                "addresses_truncated": False,
            }
        ],
    }


def test_constant_find_zero_limit_returns_nothing() -> None:
    function = FakeFunction("f", 0x1000, 0x1010)
    view = FakeBinaryView(functions=[function], constant_references=[(1, 0x1008, function)])
    _, find = get_tool("rex_constant_find")
    assert find(_call(view), value=1, limit=0) == {"total": 1, "truncated": True, "functions": []}


def test_constant_find_offset_and_limit() -> None:
    view = _constant_view()
    _, find = get_tool("rex_constant_find")
    limited = find(_call(view), value=0x31337, limit=1)
    assert limited["truncated"] is True
    assert [entry["name"] for entry in limited["functions"]] == ["main"]
    paged = find(_call(view), value=0x31337, limit=1, offset=1)
    assert paged["truncated"] is False
    assert [entry["name"] for entry in paged["functions"]] == ["handler"]
    assert find(_call(view), value=0x31337, function_filter="nomatch")["functions"] == []
    filtered = find(_call(view), value=0x31337, function_filter="^main$")
    assert [entry["name"] for entry in filtered["functions"]] == ["main"]
    # The docstring promises a case-insensitive name match; pin it with a
    # case-mismatched positive, not just a same-case one.
    caseless = find(_call(view), value=0x31337, function_filter="^HANDLER$")
    assert [entry["name"] for entry in caseless["functions"]] == ["handler"]
    # A page past the end is detectable, not silent: the empty page carries the exact
    # total, which sits below the requested offset.
    assert find(_call(view), value=0x31337, limit=5, offset=5) == {
        "total": 2,
        "truncated": False,
        "functions": [],
    }


def _interleaved_constant_view() -> FakeBinaryView:
    split = FakeFunction("split", 0x1000, 0x1100)
    between = FakeFunction("between", 0x1040, 0x1060)
    return FakeBinaryView(
        functions=[split, between],
        constant_references=[
            (7, 0x1010, split),
            (7, 0x1050, between),
            (7, 0x1080, split),
        ],
    )


def test_constant_find_merges_a_function_split_around_another() -> None:
    view = _interleaved_constant_view()
    _, find = get_tool("rex_constant_find")
    assert find(_call(view), value=7) == {
        "total": 2,
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "split",
                "addresses": ["0x1010", "0x1080"],
                "addresses_truncated": False,
            },
            {
                "start": "0x1040",
                "name": "between",
                "addresses": ["0x1050"],
                "addresses_truncated": False,
            },
        ],
    }


def test_constant_find_pages_a_split_function_once() -> None:
    view = _interleaved_constant_view()
    _, find = get_tool("rex_constant_find")
    second = find(_call(view), value=7, limit=1, offset=1)
    assert second["total"] == 2
    assert second["truncated"] is False
    assert [entry["name"] for entry in second["functions"]] == ["between"]
    first = find(_call(view), value=7, limit=1)
    assert first["total"] == 2
    assert first["truncated"] is True
    assert [entry["name"] for entry in first["functions"]] == ["split"]


def test_constant_find_merges_one_address_reported_for_overlapping_functions() -> None:
    first = FakeFunction("first", 0x1000, 0x1100)
    second = FakeFunction("second", 0x1020, 0x1100)
    view = FakeBinaryView(
        functions=[first, second],
        constant_references=[(7, 0x1030, first), (7, 0x1030, second), (7, 0x1040, first)],
    )
    _, find = get_tool("rex_constant_find")
    result = find(_call(view), value=7)
    assert result["total"] == 2
    assert [(entry["name"], entry["addresses"]) for entry in result["functions"]] == [
        ("first", ["0x1030", "0x1040"]),
        ("second", ["0x1030"]),
    ]


def test_constant_find_stops_the_scan_at_the_limit() -> None:
    functions = [
        FakeFunction(f"f{index}", 0x1000 + index * 0x10, 0x1010 + index * 0x10)
        for index in range(5)
    ]
    view = FakeBinaryView(
        functions=functions,
        constant_references=[(1, function.start + 8, function) for function in functions],
    )
    _, find = get_tool("rex_constant_find")
    result = find(_call(view), value=1, limit=2)
    assert result["truncated"] is True
    assert len(result["functions"]) == 2
    # The count seen includes the lookahead match that proved truncation.
    assert result["total"] == 3
    # The window holds 2 functions and the next match proves more exist; the scan
    # must have stopped there instead of running to the end of the view.
    assert view.constant_scan_yields == 3
    # The decline must reach the search as an abort, not just stop the local loop.
    assert view.constant_scan_aborted is True


def test_constant_find_names_the_function_filter_in_an_invalid_regex() -> None:
    _, find = get_tool("rex_constant_find")
    with pytest.raises(FakeToolError) as exc:
        find(_call(_constant_view()), value=0x31337, function_filter="[")
    assert exc.value.code == "invalid_regex"
    assert exc.value.message == (
        "Invalid regular expression parameter 'function_filter': "
        "unterminated character set at position 0"
    )


def test_constant_find_rejects_out_of_range_value() -> None:
    view = _constant_view()
    _, find = get_tool("rex_constant_find")
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), value=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'value': Must be at least 0"
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), value=2**64)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'value': Must be at most {scanning._MAX_CONSTANT_VALUE}"
    )


def test_constant_find_rejects_out_of_range_limit() -> None:
    view = _view_with_functions()
    _, find = get_tool("rex_constant_find")
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), value=1, limit=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), value=1, limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )


def test_constant_find_caps_limit_and_truncates_names() -> None:
    functions = [
        FakeFunction(
            "f" * 1000 if index == 0 else f"f{index}", 0x1000 + index * 0x10, 0x1010 + index * 0x10
        )
        for index in range(tools._MAX_LIMIT + 100)
    ]
    view = FakeBinaryView(
        functions=functions,
        constant_references=[(1, function.start + 8, function) for function in functions],
    )
    _, find = get_tool("rex_constant_find")
    result = find(_call(view), value=1, limit=tools._MAX_LIMIT)
    assert len(result["functions"]) == tools._MAX_LIMIT
    assert result["truncated"] is True
    assert result["total"] == tools._MAX_LIMIT + 1
    assert result["functions"][0]["name"].endswith("chars truncated]")


def test_data_find_rejects_negative_offset() -> None:
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)], memory={0x1000: b"\xeb\x0e\xeb\x0e\xff\xff\xff\xff"}
    )
    _, find = get_tool("rex_data_find")
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern="eb0e", limit=1, offset=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"
    # Nothing ran: the rejection happens before any segment is read.
    assert find(_call(view), pattern="eb0e", limit=1, offset=0)["total"] == 2


def test_data_find_rejects_out_of_range_limit() -> None:
    view = FakeBinaryView(segments=[FakeSegment(0x1000, 8)], memory={0x1000: b"\x90" * 8})
    _, find = get_tool("rex_data_find")
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern="90", limit=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern="90", limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )


def test_data_find_rejects_oversized_pattern() -> None:
    view = FakeBinaryView(segments=[FakeSegment(0x1000, 4)], memory={0x1000: b"\x90\x90\x90\x90"})
    _, find = get_tool("rex_data_find")
    oversized = "90" * (scanning._MAX_PATTERN_CHARS // 2 + 1)
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern=oversized)
    assert exc.value.code == "pattern_too_large"
    assert exc.value.message == f"pattern exceeds {scanning._MAX_PATTERN_CHARS} characters"
    # A pattern of exactly the cap is still accepted (it just cannot match 4 bytes).
    boundary = "90" * (scanning._MAX_PATTERN_CHARS // 2)
    assert find(_call(view), pattern=boundary)["total"] == 0


def test_search_tools_report_empty_results_on_an_empty_view() -> None:
    view = FakeBinaryView()
    _, search = get_tool("rex_string_search")
    assert search(_call(view), pattern="x") == {"total": 0, "truncated": False, "strings": []}
    _, find = get_tool("rex_data_find")
    assert find(_call(view), pattern="90") == {"total": 0, "truncated": False, "matches": []}
    _, constant_find = get_tool("rex_constant_find")
    assert constant_find(_call(view), value=1) == {"total": 0, "truncated": False, "functions": []}
    _, tag_list = get_tool("rex_tag_list")
    assert tag_list(_call(view)) == {"total": 0, "truncated": False, "tags": []}
    _, containing = get_tool("rex_function_containing")
    with pytest.raises(FakeToolError) as exc:
        containing(_call(view), 0x1000)
    assert exc.value.code == "no_function"
    # Scan-style tools answer "no function", argument-validating tools "analyzed function".
    assert exc.value.message == "no function contains 0x1000"


def _find_functions_view() -> FakeBinaryView:
    return FakeBinaryView(
        segments=[
            FakeSegment(0x1000, 0x10),
            FakeSegment(0x2000, 0x10),
            FakeSegment(0x9000, 0x10),
        ],
        memory={
            0x1000: b"\xeb\x0e\x90\x90" * 4,
            0x2000: b"\xeb\x0e" + b"\x90" * 14,
            # This match belongs to no analyzed function and must be skipped.
            0x9000: b"\xeb\x0e" + b"\x90" * 14,
        },
        functions=[FakeFunction("main", 0x1000, 0x1100), FakeFunction("handler", 0x2000, 0x2100)],
    )


def test_find_functions_by_pattern_reports_containing_functions() -> None:
    view = _find_functions_view()
    _, find = get_tool("rex_find_functions_by_pattern")
    result = find(_call(view), "eb 0e")
    # Functions come back in first-match order; the 0x9000 match is inside no function
    # and shows up in no entry.
    assert result == {
        "total": 2,
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "main",
                "match_count": 4,
                "addresses": ["0x1000", "0x1004", "0x1008", "0x100c"],
                "addresses_truncated": False,
            },
            {
                "start": "0x2000",
                "name": "handler",
                "match_count": 1,
                "addresses": ["0x2000"],
                "addresses_truncated": False,
            },
        ],
    }


def test_find_functions_by_pattern_caps_examples_at_five() -> None:
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 0x10)],
        memory={0x1000: b"\xeb\x0e" * 8},
        functions=[FakeFunction("f", 0x1000, 0x1100)],
    )
    _, find = get_tool("rex_find_functions_by_pattern")
    result = find(_call(view), "eb0e")
    # The count stays true while the example list is capped at the first 5 addresses;
    # the truncation flag says the example list was clipped.
    assert result == {
        "total": 1,
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "f",
                "match_count": 8,
                "addresses": [hex(0x1000 + 2 * index) for index in range(5)],
                "addresses_truncated": True,
            }
        ],
    }
    # Exactly at the cap the list is whole, not flagged as clipped.
    five_view = FakeBinaryView(
        segments=[FakeSegment(0x2000, 10)],
        memory={0x2000: b"\xeb\x0e" * 5},
        functions=[FakeFunction("g", 0x2000, 0x2100)],
    )
    assert find(_call(five_view), "eb0e") == {
        "total": 1,
        "truncated": False,
        "functions": [
            {
                "start": "0x2000",
                "name": "g",
                "match_count": 5,
                "addresses": [hex(0x2000 + 2 * index) for index in range(5)],
                "addresses_truncated": False,
            }
        ],
    }


def test_find_functions_by_pattern_limits_offsets_and_truncates() -> None:
    view = _find_functions_view()
    _, find = get_tool("rex_find_functions_by_pattern")
    limited = find(_call(view), "eb0e", limit=1)
    assert limited["truncated"] is True
    assert [entry["name"] for entry in limited["functions"]] == ["main"]
    paged = find(_call(view), "eb0e", limit=1, offset=1)
    assert paged["truncated"] is False
    assert [entry["name"] for entry in paged["functions"]] == ["handler"]
    assert paged["functions"][0]["match_count"] == 1
    # limit=0 pages nothing out; the scan stops at the first matching function past the
    # empty window, so truncated says a further one existed.
    assert find(_call(view), "eb0e", limit=0) == {"total": 1, "truncated": True, "functions": []}
    # A page past the end is detectable, not silent: the empty page carries the exact
    # total, which sits below the requested offset.
    assert find(_call(view), "eb0e", offset=5) == {"total": 2, "truncated": False, "functions": []}
    for kwargs, message in (
        ({"limit": -1}, "Invalid integer parameter 'limit': Must be at least 0"),
        (
            {"limit": tools._MAX_LIMIT + 1},
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}",
        ),
        ({"offset": -1}, "Invalid integer parameter 'offset': Must be at least 0"),
    ):
        with pytest.raises(FakeToolError) as exc:
            find(_call(view), "eb0e", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message


def test_find_functions_by_pattern_maps_matches_across_chunk_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tools, "_READ_CHUNK", 4)
    _, find = get_tool("rex_find_functions_by_pattern")
    # A match straddling the chunk edge is only visible because each read extends
    # pattern_length - 1 bytes past the chunk; it must land in the containing function.
    straddle = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x00\x33\xeb\x00\x00\x00"},
        functions=[FakeFunction("f", 0x1000, 0x1100)],
    )
    assert find(_call(straddle), "33 eb") == {
        "total": 1,
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "f",
                "match_count": 1,
                "addresses": ["0x1003"],
                "addresses_truncated": False,
            }
        ],
    }
    # A match starting exactly at the chunk edge is reported once: the reads overlap,
    # but every match start belongs to exactly one read.
    boundary = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x00\x00\x33\xeb\x00\x00"},
        functions=[FakeFunction("f", 0x1000, 0x1100)],
    )
    assert find(_call(boundary), "33 eb") == {
        "total": 1,
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "f",
                "match_count": 1,
                "addresses": ["0x1004"],
                "addresses_truncated": False,
            }
        ],
    }


def test_find_functions_by_pattern_rejects_invalid_patterns() -> None:
    view = _find_functions_view()
    _, find = get_tool("rex_find_functions_by_pattern")
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), "zz")
    assert exc.value.code == "invalid_pattern"
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), "")
    assert exc.value.code == "invalid_pattern"
    oversized = "90" * (scanning._MAX_PATTERN_CHARS // 2 + 1)
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), oversized)
    assert exc.value.code == "pattern_too_large"


def test_find_functions_by_pattern_reports_empty_results_on_empty_views() -> None:
    _, find = get_tool("rex_find_functions_by_pattern")
    # No segments at all: an empty result is valid, not an error.
    assert find(_call(FakeBinaryView()), "eb0e") == {
        "total": 0,
        "truncated": False,
        "functions": [],
    }
    # Pattern bytes exist but no analyzed function covers them: matches are skipped.
    uncovered = FakeBinaryView(
        segments=[FakeSegment(0x1000, 4)], memory={0x1000: b"\xeb\x0e\x90\x90"}
    )
    assert find(_call(uncovered), "eb0e") == {"total": 0, "truncated": False, "functions": []}
    # An unreadable segment contributes nothing.
    unreadable = FakeBinaryView(
        segments=[FakeSegment(0x9000, 4)],
        memory={0x1000: b"\xeb\x0e"},
        functions=[FakeFunction("f", 0x1000, 0x1100)],
    )
    assert find(_call(unreadable), "eb0e") == {"total": 0, "truncated": False, "functions": []}


def test_find_functions_by_pattern_uses_the_first_of_overlapping_functions() -> None:
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x00\x00\xeb\x0e\x00\x00"},
        functions=[FakeFunction("narrow", 0x1004, 0x1008), FakeFunction("wide", 0x1000, 0x1100)],
    )
    _, find = get_tool("rex_find_functions_by_pattern")
    assert find(_call(view), "eb0e") == {
        "total": 1,
        "truncated": False,
        "functions": [
            {
                "start": "0x1004",
                "name": "narrow",
                "match_count": 1,
                "addresses": ["0x1004"],
                "addresses_truncated": False,
            }
        ],
    }


def test_find_functions_by_pattern_stops_scanning_past_the_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tools, "_READ_CHUNK", 16)
    count = 20
    view = SpyBinaryView(
        segments=[FakeSegment(0x1000, 16 * count)],
        memory={0x1000: (b"\xeb\x0e" + b"\x90" * 14) * count},
        functions=[
            FakeFunction(f"f{index}", 0x1000 + 16 * index, 0x1010 + 16 * index)
            for index in range(count)
        ],
    )
    _, find = get_tool("rex_find_functions_by_pattern")
    result = find(_call(view), "eb0e", limit=1)
    assert result["truncated"] is True
    assert [entry["name"] for entry in result["functions"]] == ["f0"]
    # The count seen includes the lookahead function that proved truncation.
    assert result["total"] == 2
    # The second function's match proves truncation; no later chunk is read or looked up.
    assert view.lookup_addresses == [0x1000, 0x1010]
    assert view.read_addresses == [0x1000, 0x1010]
