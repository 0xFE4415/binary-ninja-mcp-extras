from __future__ import annotations

from pathlib import Path
from typing import override

import pytest
from helpers import (
    TYPE_LIBRARIES_ON_DISK,
    FakeActiveAnalysisInfo,
    FakeAnalysisInfo,
    FakeAnalysisProgress,
    FakeAnalysisState,
    FakeArchitecture,
    FakeBinaryView,
    FakeComponent,
    FakeDerivedString,
    FakeDerivedStringLocation,
    FakeFileMetadata,
    FakeFunction,
    FakeReferenceSource,
    FakeSegment,
    FakeStringReference,
    FakeStructureMember,
    FakeStructureType,
    FakeSymbol,
    FakeToolCall,
    FakeToolError,
    FakeType,
    FakeTypeLibrary,
    RenderableText,
    SpyBinaryView,
    get_tool,
)

from binja_plugin import tools


def _call(view: FakeBinaryView) -> FakeToolCall:
    return FakeToolCall(view)


def _view_with_functions() -> FakeBinaryView:
    main = FakeFunction(
        "main",
        0x1100,
        0x1200,
        hlil=RenderableText("void main() {\n    if (recv(fd, buf, n) <= 0)\n        return 1;\n}"),
    )
    handler = FakeFunction("handler", 0x2000, 0x2100)
    sink = FakeFunction("sink", 0x3000, 0x3100)
    main.callers = [handler]
    handler.callers = [sink]
    sink.callees = [handler]
    handler.callees = [main]
    return FakeBinaryView(functions=[main, handler, sink])


def test_string_search_matches_substring() -> None:
    view = FakeBinaryView(
        strings=[
            FakeStringReference("hello world", 0x1100),
            FakeStringReference("HELLO again", 0x1120, type_name="Utf8String"),
        ]
    )
    _, search = get_tool("rex_string_search")
    assert search(_call(view), pattern="hello")["total"] == 1
    assert search(_call(view), pattern="hello", ignore_case=True)["total"] == 2
    assert search(_call(view))["total"] == 2


def test_string_search_filters_and_pagination() -> None:
    strings = [
        FakeStringReference("alpha", 0x100),
        FakeStringReference("beta", 0x110),
        FakeStringReference("alphabeta", 0x120, type_name="Utf8String"),
    ]
    view = FakeBinaryView(strings=strings, sections={"s": (0x100, 0x118)})
    _, search = get_tool("rex_string_search")
    # "[ab]" is only matchable in regex mode: dropping the regex path yields 0 here.
    assert search(_call(view), pattern="alph[ab]", regex=True)["total"] == 2
    by_type = search(_call(view), pattern="alpha", string_type="Utf8String")
    assert by_type["total"] == 1
    assert by_type["strings"][0]["value"] == "alphabeta"
    assert search(_call(view), section="s")["total"] == 2
    paged = search(_call(view), limit=1, offset=1)
    assert paged["total"] == 3
    assert paged["strings"][0]["value"] == "beta"
    assert paged["truncated"] is True


def test_string_search_caps_limit() -> None:
    strings = [FakeStringReference(f"s{index}", 0x1000 + index) for index in range(600)]
    view = FakeBinaryView(strings=strings)
    _, search = get_tool("rex_string_search")
    # Exactly at the cap the limit is honored; the scan stops one match past the window.
    result = search(_call(view), limit=tools._MAX_LIMIT)
    assert result["total"] == tools._MAX_LIMIT + 1
    assert len(result["strings"]) == tools._MAX_LIMIT
    assert result["truncated"] is True
    # Past the cap the request is rejected, not silently normalized.
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )


def test_string_search_truncates_long_values() -> None:
    view = FakeBinaryView(strings=[FakeStringReference("a" * 600, 0x1000)])
    _, search = get_tool("rex_string_search")
    result = search(_call(view), pattern="a")
    assert result["total"] == 1
    assert result["strings"][0]["value"] == "a" * tools._MAX_CHARS + "... [88 chars truncated]"


def test_truncate_honors_custom_limit() -> None:
    assert tools._truncate("abcdef", 3) == "abc... [3 chars truncated]"


def test_string_search_pagination_beyond_the_result_set() -> None:
    view = FakeBinaryView(
        strings=[FakeStringReference("ab", 0x100), FakeStringReference("ab", 0x110)]
    )
    _, search = get_tool("rex_string_search")
    # offset == total and offset > total: empty page, nothing skipped, nothing truncated.
    at_end = search(_call(view), pattern="ab", limit=10, offset=2)
    assert at_end == {"total": 2, "truncated": False, "strings": []}
    past_end = search(_call(view), pattern="ab", limit=10, offset=10**9)
    assert past_end == {"total": 2, "truncated": False, "strings": []}
    # limit=0 pages nothing out; the scan stops at the first match past the empty window,
    # so "total" caps at offset+limit+1 and truncated says a further match existed.
    zero = search(_call(view), pattern="ab", limit=0)
    assert zero == {"total": 1, "truncated": True, "strings": []}


def test_string_search_errors() -> None:
    view = FakeBinaryView()
    _, search = get_tool("rex_string_search")
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), section="nope")
    assert exc.value.code == "section_not_found"
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), pattern="(", regex=True)
    assert exc.value.code == "invalid_regex"
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), section="s" * 1000)
    assert exc.value.code == "section_not_found"
    assert "chars truncated]" in exc.value.message
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), limit=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )


def test_string_search_section_includes_its_start_and_excludes_its_end() -> None:
    view = FakeBinaryView(
        strings=[
            FakeStringReference("before", 0xFF),
            FakeStringReference("first", 0x100),
            FakeStringReference("last", 0x11F),
            FakeStringReference("at-end", 0x120),
        ],
        sections={"s": (0x100, 0x120)},
    )
    _, search = get_tool("rex_string_search")
    values = [entry["value"] for entry in search(_call(view), section="s")["strings"]]
    assert values == ["first", "last"]


def test_string_search_reports_an_invalid_regex_before_a_missing_section() -> None:
    _, search = get_tool("rex_string_search")
    with pytest.raises(FakeToolError) as exc:
        search(_call(FakeBinaryView()), pattern="(", regex=True, section="nope")
    assert exc.value.code == "invalid_regex"


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


class FakeDisassemblyLine:
    """Mirrors the DisassemblyTextLine fields rex_disasm_at reads."""

    def __init__(self, address: int | None, text: str) -> None:
        self.address = address
        self.tokens = [text]


class FakeBasicBlock:
    def __init__(self, lines: list[tuple[int | None, str]]) -> None:
        self._lines = lines

    def get_disassembly_text(self) -> list[FakeDisassemblyLine]:
        return [FakeDisassemblyLine(address, text) for address, text in self._lines]


class FakeDisasmFunction(FakeFunction):
    """FakeFunction with the basic_blocks attribute rex_disasm_at reads."""

    def __init__(
        self,
        name: str,
        start: int,
        end: int,
        blocks: list[FakeBasicBlock],
        hlil: object = None,
    ) -> None:
        super().__init__(name, start, end, hlil=hlil)
        self.basic_blocks = blocks


def _disasm_view() -> FakeBinaryView:
    main = FakeDisasmFunction(
        "main",
        0x1100,
        0x1200,
        blocks=[
            FakeBasicBlock(
                [
                    (0x1100, "push rbp"),
                    (0x1101, "mov rbp, rsp"),
                    (0x1104, "sub rsp, 0x20"),
                    (0x1108, "mov eax, 1"),
                    (0x110D, "leave"),
                    (0x110E, "ret"),
                ]
            )
        ],
    )
    handler = FakeDisasmFunction(
        "handler", 0x2000, 0x2100, blocks=[FakeBasicBlock([(0x2000, "push rbp"), (0x2001, "ret")])]
    )
    return FakeBinaryView(functions=[main, handler])


def test_disasm_at_returns_function_and_window() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(view), 0x1104)
    assert result == {
        "function": {"start": "0x1100", "name": "main"},
        "instructions": [
            {"address": "0x1100", "text": "push rbp"},
            {"address": "0x1101", "text": "mov rbp, rsp"},
            {"address": "0x1104", "text": "sub rsp, 0x20"},
            {"address": "0x1108", "text": "mov eax, 1"},
            {"address": "0x110d", "text": "leave"},
            {"address": "0x110e", "text": "ret"},
        ],
        "truncated": False,
    }


def test_disasm_at_truncates_at_function_edges() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_at")
    # "before" reaching past the first line just starts the window at the function start,
    # and the truncation flag says the head was clipped, not that anything failed.
    head = disasm(_call(view), 0x1101, before=4, after=1)
    assert [entry["address"] for entry in head["instructions"]] == ["0x1100", "0x1101", "0x1104"]
    assert head["truncated"] is True
    tail = disasm(_call(view), 0x110D, before=1, after=8)
    assert [entry["address"] for entry in tail["instructions"]] == ["0x1108", "0x110d", "0x110e"]
    assert tail["truncated"] is True


def test_disasm_at_anchors_inside_the_containing_instruction() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_at")
    # 0x1105 falls inside "sub rsp, 0x20" (0x1104): the anchor moves down to its start.
    inside = disasm(_call(view), 0x1105, before=0, after=0)
    assert inside["instructions"] == [{"address": "0x1104", "text": "sub rsp, 0x20"}]
    assert inside["truncated"] is True
    # An address in the function's range but past the last rendered line anchors at the
    # last line instead of failing.
    past = disasm(_call(view), 0x1150, before=1, after=0)
    assert [entry["address"] for entry in past["instructions"]] == ["0x110d", "0x110e"]


def test_disasm_at_anchors_past_label_lines() -> None:
    # A label line shares the anchor's address with the instruction it names; the
    # instruction wins the anchor, and the label only shows up inside the window.
    main = FakeDisasmFunction(
        "main",
        0x1100,
        0x1200,
        blocks=[FakeBasicBlock([(0x1100, "loc_1100:"), (0x1100, "push rbp"), (0x1101, "ret")])],
    )
    view = FakeBinaryView(functions=[main])
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(view), 0x1100, before=0, after=1)
    assert result["instructions"] == [
        {"address": "0x1100", "text": "push rbp"},
        {"address": "0x1101", "text": "ret"},
    ]
    assert result["truncated"] is True


def test_disasm_at_joins_tokens_without_separators() -> None:
    class SplitTokenBlock(FakeBasicBlock):
        @override
        def get_disassembly_text(self) -> list[FakeDisassemblyLine]:
            lines = super().get_disassembly_text()
            lines[0].tokens = ["mov", " ", "rax"]
            return lines

    main = FakeDisasmFunction(
        "main", 0x1100, 0x1200, blocks=[SplitTokenBlock([(0x1100, "unused")])]
    )
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(FakeBinaryView(functions=[main])), 0x1100, before=0, after=0)
    assert result["instructions"] == [{"address": "0x1100", "text": "mov rax"}]


def test_disasm_at_preserves_equal_address_line_order() -> None:
    main = FakeDisasmFunction(
        "main",
        0x1100,
        0x1200,
        blocks=[FakeBasicBlock([(0x1100, "z_label:"), (0x1100, "a_instruction")])],
    )
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(FakeBinaryView(functions=[main])), 0x1100, before=0, after=0)
    assert result["instructions"] == [{"address": "0x1100", "text": "a_instruction"}]


def test_disasm_at_skips_unaddressed_lines() -> None:
    # Renderings can emit unaddressed continuation lines (a None address): they can
    # neither anchor nor be reported, so only addressed lines reach the window.
    main = FakeDisasmFunction(
        "main",
        0x1100,
        0x1200,
        blocks=[FakeBasicBlock([(0x1100, "push rbp"), (None, "..."), (0x1101, "ret")])],
    )
    view = FakeBinaryView(functions=[main])
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(view), 0x1100, before=0, after=1)
    assert result["instructions"] == [
        {"address": "0x1100", "text": "push rbp"},
        {"address": "0x1101", "text": "ret"},
    ]
    assert result["truncated"] is False


def test_disasm_at_rejects_addresses_outside_functions() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_at")
    # The gap between the two functions, an address before the first one, and one past
    # the last are all rejected outright, never snapped to a neighboring function.
    for address in (0x1800, 0x150, 0x9000):
        with pytest.raises(FakeToolError) as exc:
            disasm(_call(view), address)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == f"no analyzed function contains {address:#x}"


def test_disasm_at_rejects_out_of_range_window() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_at")
    # Zero and the cap are inclusive; one past the cap is rejected, not clamped down.
    capped = disasm(_call(view), 0x1104, before=0, after=tools._MAX_DISASM_CONTEXT)
    assert [entry["address"] for entry in capped["instructions"]] == [
        "0x1104",
        "0x1108",
        "0x110d",
        "0x110e",
    ]
    assert capped["truncated"] is True
    for kwargs, message in (
        ({"before": -1}, "Invalid integer parameter 'before': Must be at least 0"),
        ({"after": -1}, "Invalid integer parameter 'after': Must be at least 0"),
        (
            {"before": tools._MAX_DISASM_CONTEXT + 1},
            f"Invalid integer parameter 'before': Must be at most {tools._MAX_DISASM_CONTEXT}",
        ),
        (
            {"after": tools._MAX_DISASM_CONTEXT + 1},
            f"Invalid integer parameter 'after': Must be at most {tools._MAX_DISASM_CONTEXT}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            disasm(_call(view), 0x1104, **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Window sizes are validated before the address is even looked up: on a view with no
    # functions the range error wins over the no-function error.
    with pytest.raises(FakeToolError) as exc:
        disasm(_call(FakeBinaryView()), 0x1104, before=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'before': Must be at least 0"


def test_disasm_at_truncates_names_and_text() -> None:
    main = FakeDisasmFunction(
        "m" * 600, 0x1100, 0x1200, blocks=[FakeBasicBlock([(0x1100, "x" * 600)])]
    )
    view = FakeBinaryView(functions=[main])
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(view), 0x1100, before=0, after=0)
    assert result["function"]["name"].endswith("chars truncated]")
    assert result["instructions"][0]["text"].endswith("chars truncated]")


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
        "truncated": False,
        "functions": [
            {"start": "0x1100", "name": "main", "addresses": ["0x1140", "0x1150"]},
            {"start": "0x2000", "name": "handler", "addresses": ["0x2050"]},
        ],
    }
    assert find(_call(view), value=0x1234)["functions"][0]["addresses"] == ["0x3010"]


def test_constant_find_skips_lines_outside_functions() -> None:
    view = _constant_view()
    view.constant_references.append((7, 0x9000, None))
    _, find = get_tool("rex_constant_find")
    assert find(_call(view), value=7) == {"truncated": False, "functions": []}


def test_constant_find_caps_matches_per_function() -> None:
    function = FakeFunction("sink", 0x3000, 0x3100)
    view = FakeBinaryView(
        functions=[function],
        constant_references=[(7, 0x3000 + index, function) for index in range(7)],
    )
    _, find = get_tool("rex_constant_find")
    result = find(_call(view), value=7)
    assert result == {
        "truncated": False,
        "functions": [
            {
                "start": "0x3000",
                "name": "sink",
                "addresses": [hex(0x3000 + index) for index in range(6)],
            }
        ],
    }


def test_constant_find_zero_limit_returns_nothing() -> None:
    function = FakeFunction("f", 0x1000, 0x1010)
    view = FakeBinaryView(functions=[function], constant_references=[(1, 0x1008, function)])
    _, find = get_tool("rex_constant_find")
    assert find(_call(view), value=1, limit=0) == {"truncated": True, "functions": []}


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
    assert find(_call(view), value=0x31337, limit=5, offset=5) == {
        "truncated": False,
        "functions": [],
    }


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
    # The window holds 2 functions and the next match proves more exist; the scan
    # must have stopped there instead of running to the end of the view.
    assert view.constant_scan_yields == 3
    # The decline must reach the search as an abort, not just stop the local loop.
    assert view.constant_scan_aborted is True


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
        f"Invalid integer parameter 'value': Must be at most {tools._MAX_CONSTANT_VALUE}"
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
    assert result["functions"][0]["name"].endswith("chars truncated]")


def test_function_define_and_undefine() -> None:
    view = FakeBinaryView()
    _, define = get_tool("rex_function_define")
    assert define(_call(view), 0x4000) == {"start": "0x4000", "name": "sub_4000"}
    assert len(view.created_functions) == 1

    _, undefine = get_tool("rex_function_undefine")
    assert undefine(_call(view), 0x4000) == {"start": "0x4000", "name": "sub_4000"}
    assert len(view.removed_functions) == 1

    with pytest.raises(FakeToolError) as exc:
        undefine(_call(view), 0x9999)
    assert exc.value.code == "no_function"


def test_function_define_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    view = FakeBinaryView()
    monkeypatch.setattr(view, "create_user_function", lambda address: None)
    _, define = get_tool("rex_function_define")
    with pytest.raises(FakeToolError) as exc:
        define(_call(view), 0x4000)
    assert exc.value.code == "define_failed"


def test_hlil_grep_matches_lines() -> None:
    view = _view_with_functions()
    _, grep = get_tool("rex_hlil_grep")
    result = grep(_call(view), "recv")
    assert result["scanned"] == 1
    assert result["functions"] == [
        {"start": "0x1100", "name": "main", "lines": ["    if (recv(fd, buf, n) <= 0)"]}
    ]
    assert grep(_call(view), "RECV")["functions"] == []


def test_hlil_grep_supports_regex_operators() -> None:
    view = FakeBinaryView(
        functions=[FakeFunction("main", 0x1000, 0x1010, hlil=RenderableText("call rax\n"))]
    )
    _, grep = get_tool("rex_hlil_grep")
    assert grep(_call(view), r"rax+")["functions"] == [
        {"start": "0x1000", "name": "main", "lines": ["call rax"]}
    ]


def test_hlil_grep_caps_lines_per_function() -> None:
    lines = "\n".join(f"call rax_{index}" for index in range(4))
    view = FakeBinaryView(
        functions=[FakeFunction("f", 0x1000, 0x1010, hlil=RenderableText(lines + "\n"))]
    )
    _, grep = get_tool("rex_hlil_grep")
    result = grep(_call(view), "call rax")
    assert result == {
        "scanned": 1,
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "f",
                "lines": [f"call rax_{index}" for index in range(3)],
            }
        ],
        "next_offset": None,
    }


def test_hlil_grep_context_wraps_matches() -> None:
    view = _view_with_functions()
    _, grep = get_tool("rex_hlil_grep")
    # Context lines are prefixed with two spaces and the matched line with "> ", so the
    # match stays delimited inside its window.
    result = grep(_call(view), "recv", context_before=1, context_after=1)
    assert result["functions"] == [
        {
            "start": "0x1100",
            "name": "main",
            "lines": [
                "  void main() {",
                ">     if (recv(fd, buf, n) <= 0)",
                "          return 1;",
            ],
        }
    ]
    # Function edges truncate: the first HLIL line has no predecessor, so a larger
    # before-context returns fewer lines rather than padding.
    clipped = grep(_call(view), "recv", context_before=8, context_after=8)
    assert clipped["functions"][0]["lines"] == [
        "  void main() {",
        ">     if (recv(fd, buf, n) <= 0)",
        "          return 1;",
        "  }",
    ]
    # Explicit zero on both sides must stay byte-identical to the undecorated form.
    assert grep(_call(view), "recv", context_before=0, context_after=0) == grep(_call(view), "recv")


def test_hlil_grep_context_separates_and_caps_matches() -> None:
    lines = "\n".join(f"call rax_{index}" for index in range(4))
    view = FakeBinaryView(
        functions=[FakeFunction("f", 0x1000, 0x1010, hlil=RenderableText(lines + "\n"))]
    )
    _, grep = get_tool("rex_hlil_grep")
    result = grep(_call(view), "call rax", context_before=1)
    # Three matches is still the per-function cap; each match keeps its own window, and
    # "--" separates consecutive groups even where their context ranges overlap.
    assert result["functions"][0]["lines"] == [
        "> call rax_0",
        "--",
        "  call rax_0",
        "> call rax_1",
        "--",
        "  call rax_1",
        "> call rax_2",
    ]


def test_hlil_grep_context_truncates_long_lines() -> None:
    hlil = RenderableText("before\n" + "a" * 600 + "\nrecv()\nafter")
    view = FakeBinaryView(functions=[FakeFunction("f", 0x1000, 0x1010, hlil=hlil)])
    _, grep = get_tool("rex_hlil_grep")
    # Context lines go through the same per-line echo cap as matched lines.
    result = grep(_call(view), "recv", context_before=2)
    assert result["functions"][0]["lines"] == [
        "  before",
        "  " + "a" * tools._MAX_CHARS + "... [88 chars truncated]",
        "> recv()",
    ]


def test_hlil_grep_rejects_out_of_range_context() -> None:
    view = _view_with_functions()
    _, grep = get_tool("rex_hlil_grep")
    for kwargs, message in (
        ({"context_before": -1}, "Invalid integer parameter 'context_before': Must be at least 0"),
        ({"context_after": -1}, "Invalid integer parameter 'context_after': Must be at least 0"),
        (
            {"context_before": tools._MAX_HLIL_GREP_CONTEXT + 1},
            "Invalid integer parameter 'context_before': Must be at most "
            f"{tools._MAX_HLIL_GREP_CONTEXT}",
        ),
        (
            {"context_after": tools._MAX_HLIL_GREP_CONTEXT + 1},
            "Invalid integer parameter 'context_after': Must be at most "
            f"{tools._MAX_HLIL_GREP_CONTEXT}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            grep(_call(view), "recv", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message


def test_hlil_grep_limits_and_errors() -> None:
    view = _view_with_functions()
    _, grep = get_tool("rex_hlil_grep")
    skipped = grep(_call(view), ".", function_filter="handler|sink")
    assert skipped["scanned"] == 0
    assert skipped["functions"] == []
    assert skipped["truncated"] is False
    # The docstring promises a case-insensitive name match; pin it with a
    # case-mismatched positive (uppercase filter, lowercase function name).
    caseless = grep(_call(view), "recv", function_filter="MAIN")
    assert [entry["name"] for entry in caseless["functions"]] == ["main"]
    limited = grep(_call(view), ".", limit=0)
    assert limited["truncated"] is True
    assert limited["functions"] == []
    zero_scan = grep(_call(view), ".", max_functions=0)
    assert zero_scan == {"scanned": 0, "truncated": True, "functions": [], "next_offset": 0}
    with pytest.raises(FakeToolError) as exc:
        grep(_call(view), "(")
    assert exc.value.code == "invalid_regex"
    # Out-of-range sizes are rejected with the mcp layer's argument-error convention.
    for kwargs, message in (
        ({"limit": -1}, "Invalid integer parameter 'limit': Must be at least 0"),
        (
            {"limit": tools._MAX_HLIL_GREP_LIMIT + 1},
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_HLIL_GREP_LIMIT}",
        ),
        ({"max_functions": -1}, "Invalid integer parameter 'max_functions': Must be at least 0"),
        (
            {"max_functions": tools._MAX_HLIL_GREP_FUNCTIONS + 1},
            "Invalid integer parameter 'max_functions': Must be at most "
            f"{tools._MAX_HLIL_GREP_FUNCTIONS}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            grep(_call(view), ".", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message


def test_hlil_grep_caps_limit_and_max_functions() -> None:
    matching = [
        FakeFunction(
            "m" * 1000 if index == 0 else f"m{index}",
            0x1000 + index * 0x10,
            0x1010 + index * 0x10,
            hlil=RenderableText("call ax\n"),
        )
        for index in range(tools._MAX_HLIL_GREP_LIMIT + 50)
    ]
    view = FakeBinaryView(functions=matching)
    _, grep = get_tool("rex_hlil_grep")
    # Exactly at both caps the values are honored, not normalized.
    result = grep(
        _call(view),
        ".",
        limit=tools._MAX_HLIL_GREP_LIMIT,
        max_functions=tools._MAX_HLIL_GREP_FUNCTIONS,
    )
    assert len(result["functions"]) == tools._MAX_HLIL_GREP_LIMIT
    assert result["truncated"] is True
    assert result["functions"][0]["name"].endswith("chars truncated]")

    inert = [
        FakeFunction(
            f"n{index}",
            0x5000 + index * 0x10,
            0x5010 + index * 0x10,
            hlil=RenderableText("nop\n"),
        )
        for index in range(tools._MAX_HLIL_GREP_FUNCTIONS + 1)
    ]
    inert_view = FakeBinaryView(functions=inert)
    scanned_result = grep(
        _call(inert_view),
        "zzz",
        limit=tools._MAX_HLIL_GREP_LIMIT,
        max_functions=tools._MAX_HLIL_GREP_FUNCTIONS,
    )
    assert scanned_result["scanned"] == tools._MAX_HLIL_GREP_FUNCTIONS
    assert scanned_result["truncated"] is True


def test_hlil_grep_offset_and_next_offset() -> None:
    functions = [
        FakeFunction(
            f"a{index}",
            0x1000 + index * 0x10,
            0x1010 + index * 0x10,
            hlil=RenderableText("call ax\n"),
        )
        for index in range(4)
    ]
    view = FakeBinaryView(functions=functions)
    _, grep = get_tool("rex_hlil_grep")
    paged = grep(_call(view), "call", limit=2, offset=1)
    assert paged == {
        "scanned": 2,
        "truncated": True,
        "functions": [
            {"start": hex(0x1000 + index * 0x10), "name": f"a{index}", "lines": ["call ax"]}
            for index in (1, 2)
        ],
        "next_offset": 3,
    }
    resumed = grep(_call(view), "call", limit=2, offset=3)
    assert resumed == {
        "scanned": 1,
        "truncated": False,
        "functions": [{"start": "0x1030", "name": "a3", "lines": ["call ax"]}],
        "next_offset": None,
    }
    beyond = grep(_call(view), "call", offset=10)
    assert beyond == {"scanned": 0, "truncated": False, "functions": [], "next_offset": None}
    with pytest.raises(FakeToolError) as exc:
        grep(_call(view), "call", offset=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"


def test_memory_write_validates_and_writes() -> None:
    view = FakeBinaryView()
    _, write = get_tool("rex_memory_write")
    result = write(_call(view), 0x1000, "90 90")
    assert result == {"address": "0x1000", "bytes_written": 2}
    assert view.written == [(0x1000, b"\x90\x90")]
    # Whitespace of any kind separates bytes before validation; whitespace-only input
    # collapses to the empty pattern and is rejected as empty, not passed to fromhex.
    assert write(_call(view), 0x1000, "90\t90\n") == {"address": "0x1000", "bytes_written": 2}
    assert view.written[-1] == (0x1000, b"\x90\x90")
    for bad in ("", " ", "9", "zz", "9z"):
        with pytest.raises(FakeToolError) as exc:
            write(_call(view), 0x1000, bad)
        assert exc.value.code == "invalid_hex"


def test_string_read_at_truncates_and_caps_max_chars() -> None:
    view = FakeBinaryView(
        strings=[FakeStringReference("a" * 5000, 0x1100, type_name="Utf16String")]
    )
    _, read = get_tool("rex_string_read_at")
    result = read(_call(view), 0x1100)
    assert result["length"] == 5000
    assert result["type"] == "Utf16String"
    assert result["truncated"] is True
    assert len(result["value"]) == 512 + len("... [4488 chars truncated]")
    # Exactly at the cap the value is honored, never raised past _MAX_STRING_READ_CHARS.
    capped = read(_call(view), 0x1100, max_chars=tools._MAX_STRING_READ_CHARS)
    assert capped["truncated"] is True
    assert len(capped["value"]) == tools._MAX_STRING_READ_CHARS + len("... [904 chars truncated]")
    short = FakeBinaryView(strings=[FakeStringReference("hi", 0x1100)])
    assert read(_call(short), 0x1100)["truncated"] is False
    with pytest.raises(FakeToolError) as exc:
        read(_call(view), 0x2000)
    assert exc.value.code == "no_string"


def test_function_containing_caps_entries_and_truncates_names() -> None:
    inner = FakeFunction("inner", 0x1150, 0x1160)
    outer = FakeFunction("outer", 0x1100, 0x1200)
    layers = [
        FakeFunction("layer" + "x" * 600 if index == 0 else f"layer{index}", 0x1000, 0x2000)
        for index in range(tools._MAX_FUNCTION_ENTRIES + 10)
    ]
    view = FakeBinaryView(functions=[inner, outer, *layers])
    _, containing = get_tool("rex_function_containing")
    result = containing(_call(view), 0x1155)
    assert len(result["functions"]) == tools._MAX_FUNCTION_ENTRIES
    assert result["truncated"] is True
    assert result["functions"][2]["name"].endswith("chars truncated]")
    small = FakeBinaryView(functions=[inner, outer])
    assert containing(_call(small), 0x1155)["truncated"] is False
    with pytest.raises(FakeToolError) as exc:
        containing(_call(small), 0x2000)
    assert exc.value.code == "no_function"


def test_kv_set_get_delete_roundtrip() -> None:
    view = FakeBinaryView()
    _, kv_set = get_tool("rex_kv_set")
    _, kv_get = get_tool("rex_kv_get")
    _, kv_delete = get_tool("rex_kv_delete")
    assert kv_set(_call(view), "notes", "C2 at 0x401000") == {
        "key": "notes",
        "length": 14,
        "value": "C2 at 0x401000",
        "truncated": False,
    }
    assert kv_get(_call(view), "notes") == {
        "key": "notes",
        "value": "C2 at 0x401000",
        "truncated": False,
    }
    assert kv_delete(_call(view), "notes") == {"key": "notes"}
    with pytest.raises(FakeToolError) as exc:
        kv_get(_call(view), "notes")
    assert exc.value.code == "not_found"
    for name in ("rex_kv_set", "rex_kv_get", "rex_kv_delete"):
        _, function = get_tool(name)
        with pytest.raises(FakeToolError) as exc:
            if name == "rex_kv_set":
                function(_call(view), "", "")
            else:
                function(_call(view), "")
        assert exc.value.code == "invalid_key"


def test_kv_set_truncates_echo_and_rejects_oversized_value() -> None:
    view = FakeBinaryView()
    _, kv_set = get_tool("rex_kv_set")
    _, kv_get = get_tool("rex_kv_get")
    with pytest.raises(FakeToolError) as exc:
        kv_set(_call(view), "notes", "a" * (tools._MAX_KV_VALUE_CHARS + 1))
    assert exc.value.code == "value_too_large"
    assert "aaaa" not in exc.value.message
    echoed = kv_set(_call(view), "notes", "a" * 600)
    assert echoed["length"] == 600
    assert echoed["truncated"] is True
    assert len(echoed["value"]) == 512 + len("... [88 chars truncated]")
    # The stored value is untouched; only the response echo is truncated.
    assert kv_get(_call(view), "notes")["value"] == "a" * 600
    # At exactly the echo cap the value comes back whole; one past it is truncated.
    exact = kv_set(_call(view), "exact", "c" * tools._MAX_CHARS)
    assert exact["value"] == "c" * tools._MAX_CHARS
    assert exact["truncated"] is False
    one_past = kv_set(_call(view), "exact", "c" * (tools._MAX_CHARS + 1))
    assert one_past["truncated"] is True
    assert one_past["value"] == "c" * tools._MAX_CHARS + "... [1 chars truncated]"


def test_kv_get_truncates_oversized_stored_value() -> None:
    view = FakeBinaryView()
    view.store_metadata("rex/legacy", "b" * (tools._MAX_KV_VALUE_CHARS + 10))
    _, kv_get = get_tool("rex_kv_get")
    result = kv_get(_call(view), "legacy")
    assert result["truncated"] is True
    assert len(result["value"]) == tools._MAX_KV_VALUE_CHARS + len("... [10 chars truncated]")


def test_kv_error_messages_truncate_key() -> None:
    view = FakeBinaryView()
    _, kv_get = get_tool("rex_kv_get")
    with pytest.raises(FakeToolError) as exc:
        kv_get(_call(view), "k" * 1000)
    assert exc.value.code == "not_found"
    assert "chars truncated]" in exc.value.message


def test_call_paths_finds_caller_and_callee_paths() -> None:
    view = _view_with_functions()
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1100, 0x3000)
    assert result["reachable"] is True
    assert result["truncated"] is False
    assert result["paths"] == [
        [
            {"start": "0x1100", "name": "main"},
            {"start": "0x2000", "name": "handler"},
            {"start": "0x3000", "name": "sink"},
        ]
    ]
    result = paths(_call(view), 0x3000, 0x1100, direction="callees")
    assert [step["name"] for step in result["paths"][0]] == ["sink", "handler", "main"]


def test_call_paths_depth_shortcut_and_errors() -> None:
    view = _view_with_functions()
    _, paths = get_tool("rex_call_paths")
    assert paths(_call(view), 0x1100, 0x3000, max_depth=1)["reachable"] is False
    assert paths(_call(view), 0x1100, 0x1100) == {
        "reachable": True,
        "paths": [[{"start": "0x1100", "name": "main"}]],
        "truncated": False,
        "explored": 1,
    }
    with pytest.raises(FakeToolError) as exc:
        paths(_call(view), 0x7777, 0x3000)
    assert exc.value.code == "no_function"


def test_call_paths_reports_truncation_and_caps_depth() -> None:
    view = _view_with_functions()
    extra = FakeFunction("extra", 0x5000, 0x5100)
    view.functions[0].callers.append(extra)
    _, paths = get_tool("rex_call_paths")
    # The search stops with one path in hand and "extra" still queued.
    result = paths(_call(view), 0x1100, 0x3000, max_paths=1)
    assert result["reachable"] is True
    assert result["truncated"] is True
    assert len(result["paths"]) == 1

    chain = [
        FakeFunction(f"f{index}", 0x1000 + index * 0x10, 0x1010 + index * 0x10)
        for index in range(20)
    ]
    for index in range(19):
        chain[index].callers = [chain[index + 1]]
    chain_view = FakeBinaryView(functions=chain)
    chain_start, chain_end = 0x1000, 0x1000 + 19 * 0x10
    # max_depth exactly at the cap is accepted, and the cap keeps the 20-deep target
    # unreachable; one past the cap is rejected instead of clamped down.
    deep = paths(_call(chain_view), chain_start, chain_end, max_depth=tools._MAX_CALL_PATH_DEPTH)
    assert deep["reachable"] is False
    with pytest.raises(FakeToolError) as exc:
        paths(_call(chain_view), chain_start, chain_end, max_depth=tools._MAX_CALL_PATH_DEPTH + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'max_depth': Must be at most {tools._MAX_CALL_PATH_DEPTH}"
    )


def test_eval_python_executes_code() -> None:
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    result = evaluate(_call(view), "print('hi')\nresult = len(bv.functions)")
    assert result["stdout"] == "hi\n"
    assert result["stdout_truncated"] is False
    assert result["result"] == "3"
    assert result["result_truncated"] is False
    assert result["error"] is None
    assert result["error_truncated"] is False
    assert evaluate(_call(view), "1 + 1")["result"] is None
    # The exec namespace exposes the view as bv, the call itself, and the bn module alias.
    probe = evaluate(_call(view), "result = (bn is binaryninja) and (call.binary_view is bv)")
    assert probe["result"] == "True"
    assert probe["error"] is None


def test_eval_python_truncates_stdout_and_result() -> None:
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    result = evaluate(
        _call(view),
        f"print('x' * {tools._MAX_EVAL_STDOUT_CHARS + 10})\n"
        f"result = 'y' * {tools._MAX_EVAL_RESULT_CHARS + 10}",
    )
    assert result["stdout_truncated"] is True
    assert result["stdout"].startswith("x" * 10)
    assert len(result["stdout"]) == tools._MAX_EVAL_STDOUT_CHARS + len("... [11 chars truncated]")
    assert result["result_truncated"] is True
    # repr() wraps the string in quotes, so the truncated result starts with one.
    assert result["result"].startswith("'" + "y" * 10)
    assert len(result["result"]) == tools._MAX_EVAL_RESULT_CHARS + len("... [12 chars truncated]")
    assert result["error"] is None


def test_eval_python_survives_result_repr_raising() -> None:
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    # An object whose repr() raises must land in the structured error path, not escape the
    # handler; the stdout captured before the failure is still returned.
    result = evaluate(
        _call(view),
        "print('before')\n"
        "class Exploding:\n"
        "    def __repr__(self):\n"
        "        raise RuntimeError('no repr')\n"
        "result = Exploding()",
    )
    assert result["stdout"] == "before\n"
    assert result["result"] is None
    assert result["result_truncated"] is False
    assert result["error"] is not None
    assert "no repr" in result["error"]
    assert result["error_truncated"] is False


def test_eval_python_returns_truncated_error_instead_of_raising() -> None:
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    result = evaluate(_call(view), "print('before')\nraise ValueError('z' * 1000)")
    assert result["stdout"] == "before\n"
    assert result["result"] is None
    assert result["result_truncated"] is False
    assert result["error"] is not None
    assert result["error"].startswith("zzz")
    assert result["error_truncated"] is True
    assert len(result["error"]) == 512 + len("... [488 chars truncated]")


def test_tag_set_creates_missing_type() -> None:
    view = FakeBinaryView()
    _, tag_set = get_tool("rex_tag_set")
    result = tag_set(_call(view), 0x4010, "Finding", "C2 config")
    assert result == {
        "address": "0x4010",
        "tag_type": "Finding",
        "data": "C2 config",
        "data_truncated": False,
        "length": 9,
    }
    assert "Finding" in view.tag_types
    tag_set(_call(view), 0x4020, "Finding", "second")
    assert [tag.data for _, tag in view.get_tags()] == ["C2 config", "second"]


def test_tag_set_caps_data_and_truncates_echo() -> None:
    view = FakeBinaryView()
    _, tag_set = get_tool("rex_tag_set")
    with pytest.raises(FakeToolError) as exc:
        tag_set(_call(view), 0x4010, "Finding", "d" * (tools._MAX_TAG_DATA_CHARS + 1))
    assert exc.value.code == "data_too_large"
    assert "dddd" not in exc.value.message
    # A rejected call must have no side effects: no tag type created, no tag added, even
    # though the tag type check would have passed before the data check raised.
    assert view.tag_types == {}
    assert view.get_tags() == []
    # The data cap is checked before the tag type lookup regardless of create_missing.
    with pytest.raises(FakeToolError) as exc:
        tag_set(
            _call(view),
            0x4010,
            "Missing",
            "d" * (tools._MAX_TAG_DATA_CHARS + 1),
            create_missing=False,
        )
    assert exc.value.code == "data_too_large"
    with pytest.raises(FakeToolError) as exc:
        tag_set(_call(view), 0x4010, "T" * 1000, "x", create_missing=False)
    assert exc.value.code == "tag_type_not_found"
    assert "chars truncated]" in exc.value.message
    # A name past the creation cap can only be echoed if the tag type already exists.
    view.create_tag_type("F" * 1000, "\u25c6")
    result = tag_set(_call(view), 0x4010, "F" * 1000, "d" * 600)
    assert result["tag_type"].endswith("chars truncated]")
    assert result["data_truncated"] is True
    assert len(result["data"]) == 512 + len("... [88 chars truncated]")
    assert result["length"] == 600
    # The stored tag data is untouched; only the response echo is truncated.
    assert [tag.data for _, tag in view.get_tags()] == ["d" * 600]


def test_tag_set_without_create_and_listing() -> None:
    view = FakeBinaryView()
    _, tag_set = get_tool("rex_tag_set")
    with pytest.raises(FakeToolError) as exc:
        tag_set(_call(view), 0x4010, "Missing", "x", create_missing=False)
    assert exc.value.code == "tag_type_not_found"
    view.add_tag(0x4010, "Finding", "a")
    view.add_tag(0x4020, "Finding", "b")
    _, tag_list = get_tool("rex_tag_list")
    result = tag_list(_call(view), limit=1)
    assert result["total"] == 2
    assert result["truncated"] is True
    assert result["tags"][0]["data"] == "a"
    assert result["tags"][0]["data_truncated"] is False


def test_tag_list_caps_limit_and_truncates_data() -> None:
    view = FakeBinaryView()
    view.add_tag(0x1000, "Finding", "a" * 600)
    for index in range(600):
        view.add_tag(0x2000 + index, "Finding", f"n{index}")
    _, tag_list = get_tool("rex_tag_list")
    result = tag_list(_call(view), limit=tools._MAX_LIMIT)
    assert result["total"] == 601
    assert len(result["tags"]) == tools._MAX_LIMIT
    assert result["truncated"] is True
    assert result["tags"][0]["data_truncated"] is True
    assert result["tags"][0]["data"].endswith("chars truncated]")
    assert result["tags"][1]["data_truncated"] is False


def test_tag_list_rejects_out_of_range_limit() -> None:
    view = FakeBinaryView()
    view.add_tag(0x1000, "Finding", "a")
    view.add_tag(0x1100, "Finding", "b")
    _, tag_list = get_tool("rex_tag_list")
    # A negative limit is invalid on its face: rejected, never normalized to 0.
    for limit in (-1, -100):
        with pytest.raises(FakeToolError) as exc:
            tag_list(_call(view), limit=limit)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    with pytest.raises(FakeToolError) as exc:
        tag_list(_call(view), limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )
    # limit=0 pages nothing out; unlike the scan tools, "total" stays the true total.
    assert tag_list(_call(view), limit=0) == {"total": 2, "truncated": True, "tags": []}


def test_tag_list_paginates_with_offset() -> None:
    view = FakeBinaryView()
    for index in range(4):
        view.add_tag(0x1000 + index, "Finding", f"t{index}")
    _, tag_list = get_tool("rex_tag_list")
    result = tag_list(_call(view), limit=2, offset=1)
    assert result == {
        "total": 4,
        "truncated": True,
        "tags": [
            {"address": "0x1001", "tag_type": "Finding", "data": "t1", "data_truncated": False},
            {"address": "0x1002", "tag_type": "Finding", "data": "t2", "data_truncated": False},
        ],
    }
    # A page starting past the end is empty and not truncated.
    assert tag_list(_call(view), limit=2, offset=4) == {
        "total": 4,
        "truncated": False,
        "tags": [],
    }
    # A negative offset is invalid on its face: rejected, never normalized to 0.
    with pytest.raises(FakeToolError) as exc:
        tag_list(_call(view), limit=2, offset=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"


def test_string_search_rejects_negative_offset() -> None:
    view = FakeBinaryView(
        strings=[FakeStringReference("alpha", 0x100), FakeStringReference("alphabeta", 0x120)]
    )
    _, search = get_tool("rex_string_search")
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), pattern="alpha", limit=1, offset=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"
    # Nothing ran: the rejection happens before the scan.
    assert search(_call(view), pattern="alpha", limit=1, offset=0)["total"] == 2


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
    oversized = "90" * (tools._MAX_PATTERN_CHARS // 2 + 1)
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern=oversized)
    assert exc.value.code == "pattern_too_large"
    # A pattern of exactly the cap is still accepted (it just cannot match 4 bytes).
    boundary = "90" * (tools._MAX_PATTERN_CHARS // 2)
    assert find(_call(view), pattern=boundary)["total"] == 0


def test_string_read_at_rejects_out_of_range_max_chars() -> None:
    view = FakeBinaryView(strings=[FakeStringReference("hello", 0x1100)])
    _, read = get_tool("rex_string_read_at")
    # max_chars below 1 is invalid on its face: rejected, never clamped to 1.
    for max_chars in (-5, 0):
        with pytest.raises(FakeToolError) as exc:
            read(_call(view), 0x1100, max_chars=max_chars)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == "Invalid integer parameter 'max_chars': Must be at least 1"
    with pytest.raises(FakeToolError) as exc:
        read(_call(view), 0x1100, max_chars=tools._MAX_STRING_READ_CHARS + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'max_chars': Must be at most {tools._MAX_STRING_READ_CHARS}"
    )
    # Both bounds are inclusive: exactly 1 and exactly the cap are accepted.
    at_minimum = read(_call(view), 0x1100, max_chars=1)
    assert at_minimum["value"] == "h... [4 chars truncated]"
    assert at_minimum["truncated"] is True


def test_call_paths_reports_one_path_per_intermediate_and_sorts_neighbors() -> None:
    main = FakeFunction("main", 0x1100, 0x1200)
    x1 = FakeFunction("x1", 0x2000, 0x2010)
    x2 = FakeFunction("x2", 0x2100, 0x2110)
    middle = FakeFunction("middle", 0x3000, 0x3010)
    sink = FakeFunction("sink", 0x4000, 0x4010)
    # "middle" is reachable through two parents; enqueueing it once (the visited set) must
    # keep it to one expansion, so exactly one path exists despite the diamond.
    main.callers = [x1, x2]
    x1.callers = [middle]
    x2.callers = [middle]
    middle.callers = [sink]
    view = FakeBinaryView(functions=[main, x1, x2, middle, sink])
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1100, 0x4000)
    assert result == {
        "reachable": True,
        "paths": [
            [
                {"start": "0x1100", "name": "main"},
                {"start": "0x2000", "name": "x1"},
                {"start": "0x3000", "name": "middle"},
                {"start": "0x4000", "name": "sink"},
            ]
        ],
        "truncated": False,
        "explored": 4,
    }
    # Neighbors are ordered by start address, not insertion order, in both directions.
    late = FakeFunction("late", 0x9000, 0x9010)
    early = FakeFunction("early", 0x5000, 0x5010)
    target = FakeFunction("target", 0x7000, 0x7010)
    root = FakeFunction("root", 0x1100, 0x1200)
    root.callers = [late, early]
    late.callers = [target]
    early.callers = [target]
    caller_view = FakeBinaryView(functions=[root, late, early, target])
    caller_result = paths(_call(caller_view), 0x1100, 0x7000, max_paths=5)
    assert [[step["name"] for step in path] for path in caller_result["paths"]] == [
        ["root", "early", "target"],
        ["root", "late", "target"],
    ]
    root.callees = [late, early]
    late.callees = [target]
    early.callees = [target]
    callee_result = paths(_call(caller_view), 0x1100, 0x7000, direction="callees", max_paths=5)
    assert [[step["name"] for step in path] for path in callee_result["paths"]] == [
        ["root", "early", "target"],
        ["root", "late", "target"],
    ]


def test_call_paths_caps_paths_per_node() -> None:
    main = FakeFunction("main", 0x1100, 0x1200)
    handler = FakeFunction("handler", 0x2000, 0x2100)
    sink = FakeFunction("sink", 0x3000, 0x3100)
    main.callers = [handler]
    # Real BinaryView call-graph properties list one entry per call site, so the target can
    # appear several times in one neighbors list.
    handler.callers = [sink, sink, sink]
    view = FakeBinaryView(functions=[main, handler, sink])
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1100, 0x3000, max_paths=2)
    assert len(result["paths"]) == 2
    assert result["truncated"] is True


def test_call_paths_rejects_out_of_range_bounds() -> None:
    # max_paths/max_depth below 1 or above their caps are rejected, not normalized:
    # each bound is invalid on its face and both bounds are inclusive.
    view = _view_with_functions()
    _, paths = get_tool("rex_call_paths")
    for kwargs, message in (
        ({"max_paths": 0}, "Invalid integer parameter 'max_paths': Must be at least 1"),
        ({"max_paths": -1}, "Invalid integer parameter 'max_paths': Must be at least 1"),
        (
            {"max_paths": tools._MAX_CALL_PATHS + 1},
            f"Invalid integer parameter 'max_paths': Must be at most {tools._MAX_CALL_PATHS}",
        ),
        ({"max_depth": 0}, "Invalid integer parameter 'max_depth': Must be at least 1"),
        (
            {"max_depth": tools._MAX_CALL_PATH_DEPTH + 1},
            f"Invalid integer parameter 'max_depth': Must be at most {tools._MAX_CALL_PATH_DEPTH}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            paths(_call(view), 0x1100, 0x1100, **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Exactly at both caps (and at the minimum of 1) the search still runs.
    at_cap_paths = paths(_call(view), 0x1100, 0x1100, max_paths=tools._MAX_CALL_PATHS)
    assert at_cap_paths["reachable"] is True
    at_cap_depth = paths(_call(view), 0x1100, 0x1100, max_depth=tools._MAX_CALL_PATH_DEPTH)
    assert at_cap_depth["reachable"] is True


def test_tag_set_caps_new_tag_type_name() -> None:
    view = FakeBinaryView()
    _, tag_set = get_tool("rex_tag_set")
    with pytest.raises(FakeToolError) as exc:
        tag_set(_call(view), 0x4010, "T" * (tools._MAX_TAG_TYPE_CHARS + 1), "x")
    assert exc.value.code == "tag_type_too_large"
    assert view.tag_types == {}
    # A long name that already exists is still usable; only creation is capped.
    view.create_tag_type("L" * 100, "\u25c6")
    result = tag_set(_call(view), 0x4010, "L" * 100, "x")
    assert result["tag_type"] == "L" * 100


def test_kv_set_caps_key_length() -> None:
    view = FakeBinaryView()
    _, kv_set = get_tool("rex_kv_set")
    _, kv_get = get_tool("rex_kv_get")
    with pytest.raises(FakeToolError) as exc:
        kv_set(_call(view), "k" * (tools._MAX_KV_KEY_CHARS + 1), "value")
    assert exc.value.code == "key_too_large"
    # Nothing was stored under the rejected key.
    with pytest.raises(FakeToolError) as exc:
        kv_get(_call(view), "k" * (tools._MAX_KV_KEY_CHARS + 1))
    assert exc.value.code == "not_found"
    # A key of exactly the cap is still accepted.
    boundary_key = "k" * tools._MAX_KV_KEY_CHARS
    assert kv_set(_call(view), boundary_key, "value")["key"] == boundary_key
    assert view.query_metadata("rex/" + boundary_key) == "value"


def test_search_tools_report_empty_results_on_an_empty_view() -> None:
    view = FakeBinaryView()
    _, search = get_tool("rex_string_search")
    assert search(_call(view), pattern="x") == {"total": 0, "truncated": False, "strings": []}
    _, find = get_tool("rex_data_find")
    assert find(_call(view), pattern="90") == {"total": 0, "truncated": False, "matches": []}
    _, constant_find = get_tool("rex_constant_find")
    assert constant_find(_call(view), value=1) == {"truncated": False, "functions": []}
    _, tag_list = get_tool("rex_tag_list")
    assert tag_list(_call(view)) == {"total": 0, "truncated": False, "tags": []}
    _, containing = get_tool("rex_function_containing")
    with pytest.raises(FakeToolError) as exc:
        containing(_call(view), 0x1000)
    assert exc.value.code == "no_function"


class FakeParsingToolCall(FakeToolCall):
    """FakeToolCall with the parse_address surface rex_decompile_many/rex_quick_main read.

    Deliberately raises a plain ValueError for unparsable input instead of a ToolError:
    the handler owns the conversion of expression-parse failures to invalid_params, so
    the fake must not hand it an error to pass through. ``data_<hex>`` tokens resolve the
    way the core's address-expression parser was observed to resolve them live.
    """

    def parse_address(self, value: object, here: int = 0) -> int:
        text = value if isinstance(value, str) else str(value)
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
        except ValueError:
            pass
        if text.startswith("data_"):
            return int(text[5:], 16)
        raise ValueError(f"unparsable address expression '{text}'") from None


def _decompile_view() -> FakeBinaryView:
    main = FakeFunction(
        "main", 0x1100, 0x1200, hlil=RenderableText("void main() {\n    return 0;\n}")
    )
    handler = FakeFunction(
        "handler",
        0x2000,
        0x2100,
        hlil=RenderableText("void handler() {\n    recv(fd, buf, n);\n    return 1;\n}"),
    )
    # "sink" models a function that was never lifted: it contains addresses but has no HLIL.
    sink = FakeFunction("sink", 0x3000, 0x3100)
    return FakeBinaryView(functions=[main, handler, sink])


def test_decompile_many_renders_each_requested_function() -> None:
    view = _decompile_view()
    _, decompile = get_tool("rex_decompile_many")
    result = decompile(FakeParsingToolCall(view), ["0x1100", "0x2000"], max_lines=400)
    assert result == {
        "functions": [
            {
                "start": "0x1100",
                "name": "main",
                "lines": ["void main() {", "    return 0;", "}"],
                "truncated": False,
            },
            {
                "start": "0x2000",
                "name": "handler",
                "lines": ["void handler() {", "    recv(fd, buf, n);", "    return 1;", "}"],
                "truncated": False,
            },
        ]
    }
    # Output order follows the request, not address order.
    flipped = decompile(FakeParsingToolCall(view), ["0x2000", "0x1100"])
    assert [entry["name"] for entry in flipped["functions"]] == ["handler", "main"]


def test_decompile_many_truncates_lines_and_echoes() -> None:
    view = _decompile_view()
    _, decompile = get_tool("rex_decompile_many")
    clipped = decompile(FakeParsingToolCall(view), ["0x2000"], max_lines=2)
    assert clipped == {
        "functions": [
            {
                "start": "0x2000",
                "name": "handler",
                "lines": ["void handler() {", "    recv(fd, buf, n);"],
                "truncated": True,
            }
        ]
    }
    # Exactly at max_lines nothing is reported as truncated.
    exact = decompile(FakeParsingToolCall(view), ["0x2000"], max_lines=4)
    assert exact["functions"][0]["truncated"] is False
    # Rendered lines go through the same per-line echo cap as the other tools.
    long_view = FakeBinaryView(
        functions=[FakeFunction("f", 0x1000, 0x1010, hlil=RenderableText("a" * 600))]
    )
    echoed = decompile(FakeParsingToolCall(long_view), ["0x1000"])
    assert echoed["functions"][0]["lines"] == ["a" * tools._MAX_CHARS + "... [88 chars truncated]"]


def test_decompile_many_renders_unlifted_functions_as_empty() -> None:
    # A function can contain addresses without having lifted HLIL; that is an empty
    # render, not an error and not a truncation.
    view = _decompile_view()
    _, decompile = get_tool("rex_decompile_many")
    assert decompile(FakeParsingToolCall(view), ["0x3000"]) == {
        "functions": [{"start": "0x3000", "name": "sink", "lines": [], "truncated": False}]
    }


def test_decompile_many_rejects_the_whole_call_on_any_bad_entry() -> None:
    view = _decompile_view()
    _, decompile = get_tool("rex_decompile_many")
    # An unanalyzed address anywhere in the batch rejects the call: no partial results,
    # no snapping to a neighboring function.
    for batch in (["0x1100", "0x1800"], ["0x1800", "0x1100"]):
        with pytest.raises(FakeToolError) as exc:
            decompile(FakeParsingToolCall(view), batch)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == "no analyzed function contains 0x1800"
    # An unparsable expression rejects the call the same way.
    with pytest.raises(FakeToolError) as exc:
        decompile(FakeParsingToolCall(view), ["0x1100", "garbage"])
    assert exc.value.code == "invalid_params"
    assert "bad address expression" in exc.value.message


def test_decompile_many_rejects_bad_batch_and_max_lines() -> None:
    view = _decompile_view()
    _, decompile = get_tool("rex_decompile_many")
    for batch in ([], ["0x1100"] * (tools._MAX_DECOMPILE_BATCH + 1)):
        with pytest.raises(FakeToolError) as exc:
            decompile(FakeParsingToolCall(view), batch)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == (
            f"functions must contain between 1 and {tools._MAX_DECOMPILE_BATCH} address expressions"
        )
    # Exactly the batch cap is accepted.
    at_cap = decompile(FakeParsingToolCall(view), ["0x1100"] * tools._MAX_DECOMPILE_BATCH)
    assert len(at_cap["functions"]) == tools._MAX_DECOMPILE_BATCH
    # The argument must be a list of strings, not a bare value or non-string entries.
    with pytest.raises(FakeToolError) as exc:
        decompile(FakeParsingToolCall(view), "0x1100")
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "functions must be a list of address expressions"
    with pytest.raises(FakeToolError) as exc:
        decompile(FakeParsingToolCall(view), [0x1100])
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "functions[0] must be a string address expression"
    # Range errors win over address resolution, and both bounds are inclusive.
    for kwargs, message in (
        ({"max_lines": 0}, "Invalid integer parameter 'max_lines': Must be at least 1"),
        (
            {"max_lines": tools._MAX_DECOMPILE_LINES + 1},
            f"Invalid integer parameter 'max_lines': Must be at most {tools._MAX_DECOMPILE_LINES}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            decompile(FakeParsingToolCall(view), ["garbage"], **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message


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
    monkeypatch.setattr(tools.time, "sleep", clock.sleep)
    monkeypatch.setattr(tools.time, "monotonic", clock.monotonic)


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
        (tools._MAX_ANALYSIS_WAIT_MS + 1, f"at most {tools._MAX_ANALYSIS_WAIT_MS}"),
    ):
        message = f"Invalid integer parameter 'timeout_ms': Must be {requirement}"
        with pytest.raises(FakeToolError) as exc:
            wait(_call(FakeBinaryView()), timeout_ms=value)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # The range bounds themselves are accepted, not normalized.
    wait(_call(FakeBinaryView()), timeout_ms=0)
    wait(_call(FakeBinaryView()), timeout_ms=tools._MAX_ANALYSIS_WAIT_MS)
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
        for i in range(tools._MAX_ANALYSIS_INFLIGHT + 1)
    ]
    view = FakeBinaryView(
        analysis_info=FakeAnalysisInfo(FakeAnalysisState.AnalyzeState, 60, active)
    )
    _, wait = get_tool("rex_analysis_wait")
    result = wait(_call(view), timeout_ms=0)
    assert result["truncated"] is True
    assert len(result["in_flight"]) == tools._MAX_ANALYSIS_INFLIGHT
    # The cap keeps the most expensive functions, in cost order.
    assert [entry["name"] for entry in result["in_flight"]] == [
        f"f{i:02d}" for i in range(tools._MAX_ANALYSIS_INFLIGHT)
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


def _quick_main_view(entry_hlil: str | None) -> FakeBinaryView:
    """A stripped-style view: entry _start with the given HLIL, no function named main."""
    entry = FakeFunction(
        "_start",
        0x1000,
        0x1100,
        hlil=RenderableText(entry_hlil) if entry_hlil is not None else None,
    )
    main = FakeFunction(
        "sub_401234", 0x401234, 0x401400, hlil=RenderableText("void sub_401234() {\n    return;\n}")
    )
    return FakeBinaryView(entry_point=0x1000, functions=[entry, main])


def test_quick_main_resolves_main_from_the_entry_function_symbol() -> None:
    view = FakeBinaryView(
        entry_point=0x1000,
        functions=[
            FakeFunction(
                "main", 0x1000, 0x1100, hlil=RenderableText("int main() {\n    return 0;\n}")
            )
        ],
    )
    _, quick = get_tool("rex_quick_main")
    assert quick(FakeParsingToolCall(view)) == {
        "entry_point": "0x1000",
        "method": "symbol",
        "main": "0x1000",
        "note": None,
        "function": {"start": "0x1000", "name": "main"},
        "lines": ["int main() {", "    return 0;", "}"],
        "truncated": False,
    }


def test_quick_main_resolves_a_main_symbol_off_the_entry() -> None:
    # Two functions carry the symbol; the lowest address wins deterministically. The
    # entry HLIL holds no __libc_start_main, so the symbol lookup is what resolved it.
    view = FakeBinaryView(
        entry_point=0x1000,
        functions=[
            FakeFunction(
                "_start", 0x1000, 0x1100, hlil=RenderableText("void _start() {\n    return;\n}")
            ),
            FakeFunction(
                "main", 0x402000, 0x402100, hlil=RenderableText("int main() {\n    return 1;\n}")
            ),
            FakeFunction(
                "main", 0x401234, 0x401400, hlil=RenderableText("int main() {\n    return 0;\n}")
            ),
        ],
    )
    _, quick = get_tool("rex_quick_main")
    result = quick(FakeParsingToolCall(view))
    assert result["method"] == "symbol"
    assert result["main"] == "0x401234"
    assert result["function"]["name"] == "main"
    assert result["note"] is None


def test_quick_main_resolves_a_underscore_main_symbol() -> None:
    view = FakeBinaryView(
        entry_point=0x1000,
        functions=[
            FakeFunction("_start", 0x1000, 0x1100),
            FakeFunction(
                "_main", 0x2000, 0x2100, hlil=RenderableText("int _main() {\n    return 0;\n}")
            ),
        ],
    )
    _, quick = get_tool("rex_quick_main")
    result = quick(FakeParsingToolCall(view))
    assert result["method"] == "symbol"
    assert result["main"] == "0x2000"


def test_quick_main_parses_the_main_pointer_from_the_entry_hlil() -> None:
    _, quick = get_tool("rex_quick_main")
    # Data-variable token: the shape a stripped entry stub renders for the main pointer.
    data_view = _quick_main_view(
        "void _start() {\n    __libc_start_main(data_401234, __return_addr.d, &ubp_av);\n}"
    )
    result = quick(FakeParsingToolCall(data_view))
    assert result["method"] == "entry-arg"
    assert result["main"] == "0x401234"
    assert result["function"]["name"] == "sub_401234"
    assert result["note"] is None
    assert result["truncated"] is False
    # Raw pointer token: no parse_address roundtrip needed.
    hex_view = _quick_main_view(
        "void _start() {\n    __libc_start_main(0x401234, __return_addr.d);\n}"
    )
    assert quick(FakeParsingToolCall(hex_view))["main"] == "0x401234"
    # Single-argument call: the token ends at the closing parenthesis.
    only_arg_view = _quick_main_view("void _start() {\n    __libc_start_main(data_401234);\n}")
    assert quick(FakeParsingToolCall(only_arg_view))["main"] == "0x401234"
    # A pointer-deref token embeds its address: extraction must not need parse_address
    # here, and the hex digits must survive uppercase renderings.
    deref_view = _quick_main_view(
        "void _start() {\n    __libc_start_main(*0x401F00, __return_addr.d);\n}"
    )
    deref_view.functions.append(FakeFunction("sub_401f00", 0x401F00, 0x402000))
    deref_result = quick(FakeParsingToolCall(deref_view))
    assert deref_result["method"] == "entry-arg"
    assert deref_result["main"] == "0x401f00"
    assert deref_result["note"] is None


def test_quick_main_falls_back_to_the_entry_function_and_says_so() -> None:
    _, quick = get_tool("rex_quick_main")
    # No main symbol, no __libc_start_main call anywhere in the entry's HLIL.
    view = _quick_main_view("void _start() {\n    char *p = 0;\n}")
    view.functions.append(FakeFunction("handler", 0x2000, 0x2100))
    result = quick(FakeParsingToolCall(view))
    assert result["method"] == "entry-fallback"
    assert result["main"] is None
    assert result["note"] == (
        "no main symbol and no parsable __libc_start_main pointer in the entry function"
    )
    assert result["function"] == {"start": "0x1000", "name": "_start"}
    assert result["lines"] == ["void _start() {", "    char *p = 0;", "}"]


def test_first_call_argument_is_anchored_at_the_marker() -> None:
    # Direct unit tests on the helper: through the tool's small response these
    # extraction shapes are observationally identical, but the helper's exact contract
    # is what keeps resolution honest.
    extract = tools._first_call_argument
    marker = tools._MAIN_LIBC_MARKER
    assert extract("__libc_start_main(data_401234, argv)", marker) == "data_401234"
    # Spaces around the token are stripped, and only the first argument is taken.
    assert extract("__libc_start_main( data_401234 , argv)", marker) == "data_401234"
    # The paren search starts at the marker: an earlier call's "(bar)" is not taken.
    assert extract("foo(bar) __libc_start_main(data_1)", marker) == "data_1"
    # Only the first "(" after the marker opens the argument list.
    assert extract("__libc_start_main(data_401234, foo(bar))", marker) == "data_401234"
    # The marker is searched left-to-right too: a later mention must not win.
    assert extract("__libc_start_main(data_401234)  # libc_start_main wrapper", marker) == (
        "data_401234"
    )
    # A single-argument call ends at the closing parenthesis.
    assert extract("__libc_start_main(data_401234)", marker) == "data_401234"
    assert extract("__libc_start_main(data_401234))", marker) == "data_401234"
    # No opening or closing parenthesis: no argument to take.
    assert extract("tail call to __libc_start_main", marker) is None
    assert extract("libc_start_main def)", marker) is None
    assert extract("__libc_start_main(foo", marker) is None


def test_quick_main_reports_a_candidate_that_is_not_a_function() -> None:
    _, quick = get_tool("rex_quick_main")
    view = _quick_main_view("void _start() {\n    __libc_start_main(0x999999, __return_addr.d);\n}")
    result = quick(FakeParsingToolCall(view))
    assert result["method"] == "entry-fallback"
    assert result["main"] is None
    assert (
        result["note"]
        == "found candidate main address 0x999999 but no analyzed function contains it"
    )


def test_quick_main_fallback_notes_cover_the_unresolvable_entries() -> None:
    _, quick = get_tool("rex_quick_main")
    expected_note = "no main symbol and no parsable __libc_start_main pointer in the entry function"
    # Entry HLIL exists but the pointer argument renders unparsable.
    unparsable = quick(
        FakeParsingToolCall(
            _quick_main_view("void _start() {\n    __libc_start_main(argc, argv);\n}")
        )
    )
    assert unparsable["method"] == "entry-fallback"
    assert unparsable["note"] == expected_note
    # Marker present but the call never opens a parenthesis on its line.
    no_call = quick(
        FakeParsingToolCall(
            _quick_main_view(
                "void _start() {\n    // tail call to __libc_start_main\n    return;\n}"
            )
        )
    )
    assert no_call["note"] == expected_note
    # Call opens but never closes on its line, and the rest renders unparsable.
    unterminated = quick(
        FakeParsingToolCall(_quick_main_view("void _start() {\n    __libc_start_main(foo\n}"))
    )
    assert unterminated["note"] == expected_note
    # Entry never lifted: nothing to parse, HLIL comes back empty.
    unlifted = quick(FakeParsingToolCall(_quick_main_view(None)))
    assert unlifted["note"] == "the entry function has no HLIL yet"
    assert unlifted["lines"] == []
    assert unlifted["truncated"] is False


def test_quick_main_rejects_bad_max_lines_and_truncates_render() -> None:
    _, quick = get_tool("rex_quick_main")
    # Range errors are decided before the entry function is even resolved.
    for kwargs, message in (
        ({"max_lines": 0}, "Invalid integer parameter 'max_lines': Must be at least 1"),
        (
            {"max_lines": tools._MAX_DECOMPILE_LINES + 1},
            f"Invalid integer parameter 'max_lines': Must be at most {tools._MAX_DECOMPILE_LINES}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            quick(FakeParsingToolCall(FakeBinaryView()), **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # The bounds themselves are accepted.
    resolvable = FakeBinaryView(
        entry_point=0x1000, functions=[FakeFunction("main", 0x1000, 0x1100)]
    )
    quick(FakeParsingToolCall(resolvable), max_lines=1)
    quick(FakeParsingToolCall(resolvable), max_lines=tools._MAX_DECOMPILE_LINES)
    # A longer render is clipped at max_lines and flagged, and long lines go through the
    # shared echo cap.
    view = FakeBinaryView(
        entry_point=0x1000,
        functions=[
            FakeFunction(
                "main",
                0x1000,
                0x1100,
                hlil=RenderableText("a" * 600 + "\n    return 0;\n}"),
            )
        ],
    )
    result = quick(FakeParsingToolCall(view), max_lines=1)
    assert result["lines"] == ["a" * tools._MAX_CHARS + "... [88 chars truncated]"]
    assert result["truncated"] is True


def test_quick_main_resolves_an_unlifted_main_to_empty_lines() -> None:
    # A main symbol can exist where HLIL was never lifted; an empty render is the honest
    # answer, same as rex_decompile_many.
    view = FakeBinaryView(
        entry_point=0x1000,
        functions=[FakeFunction("_start", 0x1000, 0x1100), FakeFunction("main", 0x2000, 0x2100)],
    )
    _, quick = get_tool("rex_quick_main")
    result = quick(FakeParsingToolCall(view))
    assert result == {
        "entry_point": "0x1000",
        "method": "symbol",
        "main": "0x2000",
        "note": None,
        "function": {"start": "0x2000", "name": "main"},
        "lines": [],
        "truncated": False,
    }


def test_quick_main_errors_when_no_function_contains_the_entry_point() -> None:
    view = FakeBinaryView(entry_point=0x1000, functions=[FakeFunction("main", 0x2000, 0x2100)])
    _, quick = get_tool("rex_quick_main")
    with pytest.raises(FakeToolError) as exc:
        quick(FakeParsingToolCall(view))
    assert exc.value.code == "no_function"
    assert exc.value.message == "no analyzed function contains the entry point 0x1000"


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
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "main",
                "match_count": 4,
                "addresses": ["0x1000", "0x1004", "0x1008", "0x100c"],
            },
            {"start": "0x2000", "name": "handler", "match_count": 1, "addresses": ["0x2000"]},
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
    # The count stays true while the example list is capped at the first 5 addresses.
    assert result == {
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "f",
                "match_count": 8,
                "addresses": [hex(0x1000 + 2 * index) for index in range(5)],
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
    assert find(_call(view), "eb0e", limit=0) == {"truncated": True, "functions": []}
    assert find(_call(view), "eb0e", offset=5) == {"truncated": False, "functions": []}
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
        "truncated": False,
        "functions": [{"start": "0x1000", "name": "f", "match_count": 1, "addresses": ["0x1003"]}],
    }
    # A match starting exactly at the chunk edge is reported once: the reads overlap,
    # but every match start belongs to exactly one read.
    boundary = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x00\x00\x33\xeb\x00\x00"},
        functions=[FakeFunction("f", 0x1000, 0x1100)],
    )
    assert find(_call(boundary), "33 eb") == {
        "truncated": False,
        "functions": [{"start": "0x1000", "name": "f", "match_count": 1, "addresses": ["0x1004"]}],
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
    oversized = "90" * (tools._MAX_PATTERN_CHARS // 2 + 1)
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), oversized)
    assert exc.value.code == "pattern_too_large"


def test_find_functions_by_pattern_reports_empty_results_on_empty_views() -> None:
    _, find = get_tool("rex_find_functions_by_pattern")
    # No segments at all: an empty result is valid, not an error.
    assert find(_call(FakeBinaryView()), "eb0e") == {"truncated": False, "functions": []}
    # Pattern bytes exist but no analyzed function covers them: matches are skipped.
    uncovered = FakeBinaryView(
        segments=[FakeSegment(0x1000, 4)], memory={0x1000: b"\xeb\x0e\x90\x90"}
    )
    assert find(_call(uncovered), "eb0e") == {"truncated": False, "functions": []}
    # An unreadable segment contributes nothing.
    unreadable = FakeBinaryView(
        segments=[FakeSegment(0x9000, 4)],
        memory={0x1000: b"\xeb\x0e"},
        functions=[FakeFunction("f", 0x1000, 0x1100)],
    )
    assert find(_call(unreadable), "eb0e") == {"truncated": False, "functions": []}


def test_find_functions_by_pattern_uses_the_first_of_overlapping_functions() -> None:
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x00\x00\xeb\x0e\x00\x00"},
        functions=[FakeFunction("narrow", 0x1004, 0x1008), FakeFunction("wide", 0x1000, 0x1100)],
    )
    _, find = get_tool("rex_find_functions_by_pattern")
    assert find(_call(view), "eb0e") == {
        "truncated": False,
        "functions": [
            {"start": "0x1004", "name": "narrow", "match_count": 1, "addresses": ["0x1004"]}
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
    # The second function's match proves truncation; no later chunk is read or looked up.
    assert view.lookup_addresses == [0x1000, 0x1010]
    assert view.read_addresses == [0x1000, 0x1010]


# --- rex_export_disasm / rex_export_symbols -------------------------------------------------


def _use_export_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the export tools at a per-test root so nothing lands in the real home."""
    root = tmp_path / "exports"
    monkeypatch.setattr(tools, "_EXPORT_ROOT", root)
    return root


def test_export_disasm_writes_the_window_to_a_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    result = export(_call(view), 0x1104, filename="main.txt")
    expected = "push rbp\nmov rbp, rsp\nsub rsp, 0x20\nmov eax, 1\nleave\nret\n"
    assert result == {
        "path": str((root / "main.txt").resolve()),
        "bytes_written": len(expected.encode("utf-8")),
        "lines": 6,
        "truncated": False,
    }
    # Byte-exact read: read_bytes also proves the LF endings (no \r\n translation).
    assert (root / "main.txt").read_bytes() == expected.encode("utf-8")


def test_export_disasm_creates_nested_export_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "nested" / "exports"
    monkeypatch.setattr(tools, "_EXPORT_ROOT", root)
    _, export = get_tool("rex_export_disasm")
    result = export(_call(_disasm_view()), 0x1104, filename="main.txt")
    assert Path(result["path"]) == root / "main.txt"
    assert (root / "main.txt").read_bytes() == (
        b"push rbp\nmov rbp, rsp\nsub rsp, 0x20\nmov eax, 1\nleave\nret\n"
    )


def test_export_disasm_caps_the_window_at_max_lines(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    # Window of 3 lines (anchor 0x1101, before=2, after=1) clipped to 2 by max_lines.
    clipped = export(_call(view), 0x1101, before=2, after=1, max_lines=2, filename="clip.txt")
    assert clipped["lines"] == 2
    assert clipped["truncated"] is True
    assert (root / "clip.txt").read_bytes() == b"push rbp\nmov rbp, rsp\n"
    # Exactly at max_lines nothing is reported as truncated.
    exact = export(_call(view), 0x1104, max_lines=6, filename="full.txt")
    assert exact["lines"] == 6
    assert exact["truncated"] is False
    # A window clipped at a function edge also leaves rendered lines out of the file,
    # so the truncation flag fires even though no cap was hit.
    edge = export(_call(view), 0x110E, before=1, after=8, filename="edge.txt")
    assert edge["lines"] == 2
    assert edge["truncated"] is True


def test_export_disasm_shrinks_to_the_byte_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    # 36 bytes hold exactly the first three lines; the fourth ("mov eax, 1\n") would
    # push the file to 47 bytes, so it and everything after it are dropped.
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 36)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    result = export(_call(view), 0x1104, filename="shrink.txt")
    expected = b"push rbp\nmov rbp, rsp\nsub rsp, 0x20\n"
    assert result["lines"] == 3
    assert result["truncated"] is True
    assert result["bytes_written"] == len(expected)
    assert (root / "shrink.txt").read_bytes() == expected

    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", len(b"push rbp\n"))
    exact = export(_call(view), 0x1104, filename="exact.txt")
    assert exact["lines"] == 1
    assert exact["bytes_written"] == len(b"push rbp\n")
    assert exact["truncated"] is True
    assert (root / "exact.txt").read_bytes() == b"push rbp\n"


def test_export_disasm_rejects_a_single_line_over_the_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    # Even the first line ("push rbp\n" is 9 bytes) cannot fit under an 8-byte cap, so
    # shrinking from the end could never produce a file: reject instead of writing one.
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 8)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="tiny.txt")
    assert exc.value.code == "export_failed"
    assert "first entry" in exc.value.message
    # The rejection happens before any filesystem work: not even the root was created.
    assert not root.exists()


def test_export_disasm_rejects_out_of_function_addresses_and_ranges() -> None:
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    # Same rejection as rex_disasm_at: never snapped to a neighboring function.
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1800, filename="gap.txt")
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "no analyzed function contains 0x1800"
    for kwargs, message in (
        ({"before": -1}, "Invalid integer parameter 'before': Must be at least 0"),
        ({"after": -1}, "Invalid integer parameter 'after': Must be at least 0"),
        (
            {"before": tools._MAX_DISASM_CONTEXT + 1},
            f"Invalid integer parameter 'before': Must be at most {tools._MAX_DISASM_CONTEXT}",
        ),
        (
            {"after": tools._MAX_DISASM_CONTEXT + 1},
            f"Invalid integer parameter 'after': Must be at most {tools._MAX_DISASM_CONTEXT}",
        ),
        ({"max_lines": 0}, "Invalid integer parameter 'max_lines': Must be at least 1"),
        (
            {"max_lines": tools._MAX_EXPORT_DISASM_LINES + 1},
            f"Invalid integer parameter 'max_lines': Must be at most "
            f"{tools._MAX_EXPORT_DISASM_LINES}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            export(_call(view), 0x1104, filename="x.txt", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Both bounds are inclusive on every size parameter.
    at_caps = export(
        _call(view),
        0x1104,
        before=tools._MAX_DISASM_CONTEXT,
        after=tools._MAX_DISASM_CONTEXT,
        max_lines=tools._MAX_EXPORT_DISASM_LINES,
        filename="caps.txt",
    )
    assert at_caps["lines"] == 6
    # Range errors are checked before the address lookup, like rex_disasm_at.
    with pytest.raises(FakeToolError) as exc:
        export(_call(FakeBinaryView()), 0x1104, before=-1, filename="x.txt")
    assert exc.value.message == "Invalid integer parameter 'before': Must be at least 0"


def test_export_disasm_reports_export_failed_when_the_write_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "exports"
    root.mkdir()
    # A directory sitting where the file would go makes open() raise IsADirectoryError;
    # the handler must turn that into export_failed, not leak the OSError.
    (root / "occupied.txt").mkdir()
    monkeypatch.setattr(tools, "_EXPORT_ROOT", root)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="occupied.txt")
    assert exc.value.code == "export_failed"


def test_export_symbols_reports_export_failed_when_the_root_cannot_be_created(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A regular file where the export root would go makes mkdir() raise
    # NotADirectoryError; the handler must turn that into export_failed, not leak it.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    monkeypatch.setattr(tools, "_EXPORT_ROOT", blocker / "exports")
    _, export = get_tool("rex_export_symbols")
    with pytest.raises(FakeToolError) as exc:
        export(_call(_symbol_view()), 0x1000, 0x4000, filename="syms.csv")
    assert exc.value.code == "export_failed"
    assert "could not prepare export path" in exc.value.message


def test_export_disasm_fails_nested_filenames_at_the_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    # Lexical validation allows a nested relative name, but only the fixed root itself is
    # ever created on demand, so the write fails into export_failed instead of silently
    # growing a tree under the root.
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="sub/out.txt")
    assert exc.value.code == "export_failed"
    assert not (root / "sub").exists()


def test_export_disasm_accepts_a_component_at_the_name_max_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    filename = "y" * 251 + ".txt"  # exactly 255 bytes, the NAME_MAX bound
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    result = export(_call(view), 0x1104, filename=filename)
    assert result["path"] == str((root / filename).resolve())
    assert (root / filename).exists()


def test_export_disasm_rejects_a_symlink_escaping_the_export_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    root.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched")
    # A symlink planted inside the root passes the purely lexical filename validation;
    # only the containment check after resolve() can see where the write would land.
    (root / "link.txt").symlink_to(outside)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="link.txt")
    assert exc.value.code == "path_escape"
    assert str(outside) in exc.value.message
    assert outside.read_text() == "untouched"
    # resolve() follows intermediate components too, so a symlinked directory inside
    # the root cannot smuggle a write out either.
    (root / "sub").mkdir()
    (root / "sub" / "link.txt").symlink_to(outside)
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="sub/link.txt")
    assert exc.value.code == "path_escape"
    assert outside.read_text() == "untouched"


def test_type_library_export_rejects_a_symlink_escaping_the_export_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    root.mkdir(parents=True)
    outside = tmp_path / "outside.bntl"
    outside.write_bytes(b"untouched")
    (root / "link.bntl").symlink_to(outside)
    view = _typed_view()
    _, export = get_tool("rex_type_library_export")
    # The .bntl writer goes through the same resolved path as the text exports, so the
    # core-side write is contained by the same check.
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), "recovered", ["open"], filename="link.bntl")
    assert exc.value.code == "path_escape"
    assert outside.read_bytes() == b"untouched"


@pytest.mark.parametrize(
    "filename",
    [
        "/abs/path.txt",
        "up/../down.txt",
        "back\\slash.txt",
        "nul\x00byte.txt",
        "x" * 256,
        "",
    ],
)
def test_export_tools_reject_unsafe_filenames(
    filename: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    _, export_disasm = get_tool("rex_export_disasm")
    with pytest.raises(FakeToolError) as exc:
        export_disasm(_call(_disasm_view()), 0x1104, filename=filename)
    assert exc.value.code == "invalid_params"
    _, export_symbols = get_tool("rex_export_symbols")
    with pytest.raises(FakeToolError) as exc:
        export_symbols(_call(_symbol_view()), 0x1000, 0x4000, filename=filename)
    assert exc.value.code == "invalid_params"


def test_validate_export_path_rejects_each_violation_with_a_clear_message() -> None:
    cases = [
        ("", "filename must not be empty"),
        ("/etc/passwd", "filename must be a plain file name, not an absolute path"),
        ("back\\slash.txt", "filename must not contain backslashes"),
        ("nul\x00byte.txt", "filename must not contain NUL bytes"),
        ("up/../down.txt", "filename must not contain '..' path components"),
        ("x" * 256, f"filename component exceeds {tools._MAX_EXPORT_COMPONENT_BYTES} bytes"),
    ]
    for filename, message in cases:
        with pytest.raises(FakeToolError) as exc:
            tools._validate_export_path(filename)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Plain names and a component exactly at the NAME_MAX bound pass the pure validator.
    tools._validate_export_path("plain.txt")
    tools._validate_export_path("y" * 251 + ".txt")
    tools._validate_export_path("sub/plain.txt")


def _symbol_view() -> FakeBinaryView:
    # Deliberately unsorted, with symbols below and above the queried range and a name
    # containing a comma to pin the CSV quoting.
    return FakeBinaryView(
        symbols=[
            FakeSymbol(0x3000, "FunctionSymbol", "late"),
            FakeSymbol(0x5000, "DataSymbol", "outside"),
            FakeSymbol(0x1000, "FunctionSymbol", "main"),
            FakeSymbol(0x0500, "DataSymbol", "early"),
            FakeSymbol(0x2000, "DataSymbol", "msg, with comma"),
        ]
    )


def test_export_symbols_writes_a_sorted_csv_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_export_symbols")
    result = export(_call(_symbol_view()), 0x1000, 0x4000, filename="syms.csv")
    expected = (
        "symbol_address,symbol_type,name\n"
        "0x1000,FunctionSymbol,main\n"
        '0x2000,DataSymbol,"msg, with comma"\n'
        "0x3000,FunctionSymbol,late\n"
    )
    assert result == {
        "path": str((root / "syms.csv").resolve()),
        "bytes_written": len(expected.encode("utf-8")),
        "rows": 3,
        "truncated": False,
        "total": 3,
    }
    assert (root / "syms.csv").read_bytes() == expected.encode("utf-8")


def test_export_symbols_offset_limit_and_truncation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_export_symbols")
    view = _symbol_view()
    header = b"symbol_address,symbol_type,name\n"
    # The window is a slice of the address-sorted list, and pagination past the end
    # reports the true total with an empty window.
    limited = export(_call(view), 0x1000, 0x4000, limit=2, filename="page1.csv")
    assert limited["rows"] == 2
    assert limited["total"] == 3
    assert limited["truncated"] is True
    paged = export(_call(view), 0x1000, 0x4000, limit=2, offset=1, filename="page2.csv")
    assert paged["rows"] == 2
    assert paged["truncated"] is False
    assert (root / "page2.csv").read_bytes() == (
        header + b'0x2000,DataSymbol,"msg, with comma"\n' + b"0x3000,FunctionSymbol,late\n"
    )
    at_end = export(_call(view), 0x1000, 0x4000, offset=3, filename="tail.csv")
    assert at_end["rows"] == 0
    assert at_end["total"] == 3
    assert at_end["truncated"] is False
    assert (root / "tail.csv").read_bytes() == header
    # limit=0 pages nothing out but still reports that more symbols existed.
    zero = export(_call(view), 0x1000, 0x4000, limit=0, filename="empty.csv")
    assert zero["rows"] == 0
    assert zero["total"] == 3
    assert zero["truncated"] is True


def test_export_symbols_writes_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_export_symbols")
    result = export(_call(_symbol_view()), 0x1000, 0x4000, format="json", filename="syms.json")
    expected = """[
  {
    "symbol_address": "0x1000",
    "symbol_type": "FunctionSymbol",
    "name": "main"
  },
  {
    "symbol_address": "0x2000",
    "symbol_type": "DataSymbol",
    "name": "msg, with comma"
  },
  {
    "symbol_address": "0x3000",
    "symbol_type": "FunctionSymbol",
    "name": "late"
  }
]"""
    assert result["bytes_written"] == len(expected.encode("utf-8"))
    assert result["rows"] == 3
    assert result["total"] == 3
    assert result["truncated"] is False
    # Byte-exact: indented JSON, closing bracket included, no trailing newline.
    assert (root / "syms.json").read_bytes() == expected.encode("utf-8")


def test_export_symbols_shrinks_to_the_byte_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    two_rows = (
        "symbol_address,symbol_type,name\n"
        "0x1000,FunctionSymbol,main\n"
        '0x2000,DataSymbol,"msg, with comma"\n'
    )
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", len(two_rows.encode("utf-8")))
    _, export = get_tool("rex_export_symbols")
    result = export(_call(_symbol_view()), 0x1000, 0x4000, filename="capped.csv")
    # No pagination happened (the window held all three symbols), so the truncated flag
    # must come from the size drop alone.
    assert result["rows"] == 2
    assert result["total"] == 3
    assert result["truncated"] is True
    assert (root / "capped.csv").read_bytes() == two_rows.encode("utf-8")


def test_export_symbols_rejects_a_single_row_over_the_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    # The 32-byte header plus the first row can never fit under a 16-byte cap.
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 16)
    _, export = get_tool("rex_export_symbols")
    with pytest.raises(FakeToolError) as exc:
        export(_call(_symbol_view()), 0x1000, 0x4000, filename="tiny.csv")
    assert exc.value.code == "export_failed"
    assert "first entry" in exc.value.message
    assert not root.exists()


def test_export_symbols_writes_a_header_only_file_for_an_empty_range(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_export_symbols")
    result = export(_call(_symbol_view()), 0x8000, 0x9000, filename="none.csv")
    assert result == {
        "path": str((root / "none.csv").resolve()),
        "bytes_written": 32,
        "rows": 0,
        "truncated": False,
        "total": 0,
    }
    assert (root / "none.csv").read_bytes() == b"symbol_address,symbol_type,name\n"


def test_export_symbols_rejects_invalid_ranges_limits_and_format() -> None:
    view = _symbol_view()
    _, export = get_tool("rex_export_symbols")
    for kwargs, message in (
        ({"start": 0x1000, "end": 0x1000}, "end must be greater than start"),
        ({"start": 0x4000, "end": 0x1000}, "end must be greater than start"),
        ({"start": -1, "end": 0x4000}, "Invalid integer parameter 'start': Must be at least 0"),
    ):
        with pytest.raises(FakeToolError) as exc:
            export(_call(view), filename="x.csv", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    for kwargs, message in (
        ({"limit": -1}, "Invalid integer parameter 'limit': Must be at least 0"),
        (
            {"limit": tools._MAX_EXPORT_SYMBOLS + 1},
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_EXPORT_SYMBOLS}",
        ),
        ({"offset": -1}, "Invalid integer parameter 'offset': Must be at least 0"),
        ({"format": "xml"}, "format must be 'csv' or 'json', not 'xml'"),
    ):
        with pytest.raises(FakeToolError) as exc:
            export(_call(view), 0x1000, 0x4000, filename="x.csv", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Exactly at the limit cap the export still runs.
    at_cap = export(
        _call(view), 0x1000, 0x4000, limit=tools._MAX_EXPORT_SYMBOLS, filename="cap.csv"
    )
    assert at_cap["rows"] == 3


def _annotate_view() -> FakeBinaryView:
    main = FakeFunction("main", 0x1100, 0x1200)
    helper = FakeFunction("helper", 0x2000, 0x2100)
    return FakeBinaryView(functions=[main, helper])


def test_undo_and_redo_round_trip_and_report_stack_depths() -> None:
    metadata = FakeFileMetadata()
    metadata.undo_entries = ["patch bytes", "rename main"]
    view = FakeBinaryView(file=metadata)
    _, undo = get_tool("rex_undo")
    # Depths are the post-operation state: undo_left dropped, redo_left gained the entry.
    assert undo(_call(view)) == {"undone": True, "undo_left": 1, "redo_left": 1}
    assert metadata.undo_entries == ["patch bytes"]
    assert metadata.redo_entries == ["rename main"]
    _, redo = get_tool("rex_redo")
    assert redo(_call(view)) == {"redone": True, "undo_left": 2, "redo_left": 0}
    assert metadata.undo_entries == ["patch bytes", "rename main"]
    assert metadata.redo_entries == []
    # An empty stack is a core-side no-op reported as such, not an error.
    assert undo(_call(FakeBinaryView())) == {"undone": True, "undo_left": 0, "redo_left": 0}
    assert redo(_call(FakeBinaryView())) == {"redone": True, "undo_left": 0, "redo_left": 0}


def test_undo_and_redo_report_core_failures() -> None:
    metadata = FakeFileMetadata()
    metadata.undo_error = RuntimeError("no undo entries")
    view = FakeBinaryView(file=metadata)
    _, undo = get_tool("rex_undo")
    with pytest.raises(FakeToolError) as exc:
        undo(_call(view))
    assert exc.value.code == "undo_failed"
    assert "no undo entries" in exc.value.message
    metadata.redo_error = RuntimeError("no redo entries")
    _, redo = get_tool("rex_redo")
    with pytest.raises(FakeToolError) as exc:
        redo(_call(view))
    assert exc.value.code == "redo_failed"
    assert "no redo entries" in exc.value.message


def test_annotate_many_applies_name_comment_and_prototype_in_one_transaction() -> None:
    view = _annotate_view()
    main, helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [
            {"addr": "0x1150", "name": "read_config", "comment": "parses rc file"},
            {"addr": 0x2000, "prototype": "int helper(int fd)"},
        ],
    )
    # Success rows echo the annotated function's start, not the mid-function input.
    # "failed" is this tool's legacy count key; "applied"/"failed_count"/"total" are the
    # uniform batch-summary keys every batch tool now carries.
    assert result == {
        "applied": 2,
        "failed": 0,
        "failed_count": 0,
        "total": 2,
        "results": [{"addr": "0x1100", "ok": True}, {"addr": "0x2000", "ok": True}],
    }
    assert main.name == "read_config"
    assert main.comment == "parses rc file"
    assert main.user_type is None
    assert helper.name == "helper"
    assert helper.comment == ""
    assert helper.user_type == "int helper(int fd)"
    # One transaction for the whole batch: a single undo step, committed not reverted.
    assert view.transactions == ["open", "commit"]


def test_annotate_many_reports_a_missing_function_per_item() -> None:
    view = _annotate_view()
    main, _helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x1800", "name": "ghost"}, {"addr": "0x1100", "name": "renamed"}],
    )
    assert result == {
        "applied": 1,
        "failed": 1,
        "failed_count": 1,
        "total": 2,
        "results": [
            {"addr": "0x1800", "ok": False, "error": "no analyzed function contains 0x1800"},
            {"addr": "0x1100", "ok": True},
        ],
    }
    # The batch still applies and commits; only the dead item failed.
    assert main.name == "renamed"
    assert view.transactions == ["open", "commit"]


def test_annotate_many_skips_the_transaction_when_every_item_fails() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x9999", "name": "ghost"}, "not an object"],
    )
    assert result == {
        "applied": 0,
        "failed": 2,
        "failed_count": 2,
        "total": 2,
        "results": [
            {"addr": "0x9999", "ok": False, "error": "no analyzed function contains 0x9999"},
            {
                "addr": "'not an object'",
                "ok": False,
                "error": "each item must be a JSON object",
            },
        ],
    }
    # Nothing to apply, so no undo step is created at all.
    assert view.transactions == []


def test_annotate_many_reports_item_content_errors_per_item() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [
            {"comment": "no addr here"},
            {"addr": 1.5, "name": "x"},
            {"addr": True, "name": "x"},
            {"addr": "garbage"},
            {"addr": "0x1100", "name": "ok", "hue": "blue"},
        ],
    )
    (missing, mistyped, boolean, unparsable, unknown) = result["results"]
    assert missing == {
        "addr": "{'comment': 'no addr here'}",
        "ok": False,
        "error": "addr is required",
    }
    assert mistyped == {
        "addr": "1.5",
        "ok": False,
        "error": "addr must be an integer or a string address expression",
    }
    # bool is an int subclass: a JSON true/false address is a caller bug, not an address.
    assert boolean == {
        "addr": "True",
        "ok": False,
        "error": "addr must be an integer or a string address expression",
    }
    assert unparsable == {
        "addr": "garbage",
        "ok": False,
        "error": "bad address expression: unparsable address expression 'garbage'",
    }
    assert unknown == {"addr": "0x1100", "ok": False, "error": "unknown field(s): hue"}
    assert result["applied"] == 0
    assert result["failed"] == 5


def test_annotate_many_rejects_bad_batch_shape_and_size() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    with pytest.raises(FakeToolError) as exc:
        annotate(FakeParsingToolCall(view), "0x1100")
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "items must be a list of annotation objects"
    for batch in ([], [{"addr": "0x1100"}] * (tools._MAX_ANNOTATE_ITEMS + 1)):
        with pytest.raises(FakeToolError) as exc:
            annotate(FakeParsingToolCall(view), batch)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == (
            f"items must contain between 1 and {tools._MAX_ANNOTATE_ITEMS} entries"
        )
    # Exactly the batch cap is accepted.
    at_cap = annotate(
        FakeParsingToolCall(view), [{"addr": "0x1100", "name": "same"}] * tools._MAX_ANNOTATE_ITEMS
    )
    assert at_cap["applied"] == tools._MAX_ANNOTATE_ITEMS


def test_annotate_many_rejects_the_removed_type_alias_as_an_unknown_field() -> None:
    view = _annotate_view()
    main, _helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    # "prototype" is the one user-type path: "type" was its alias before the collapse and
    # is now rejected like any unknown field, so a caller cannot silently half-set a type.
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x1100", "prototype": "int main(void)", "type": "int main(void)"}],
    )
    assert result == {
        "applied": 0,
        "failed": 1,
        "failed_count": 1,
        "total": 1,
        "results": [{"addr": "0x1100", "ok": False, "error": "unknown field(s): type"}],
    }
    # The rejected item staged nothing: no type applied, no undo step created.
    assert main.user_type is None
    assert view.transactions == []


def test_annotate_many_rejects_an_unparsable_prototype_before_applying_anything() -> None:
    view = _annotate_view()
    main, _helper = view.functions
    view.parse_type_error = SyntaxError("expected ';'")
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x1100", "name": "renamed", "prototype": "int main(void)"}],
    )
    assert result == {
        "applied": 0,
        "failed": 1,
        "failed_count": 1,
        "total": 1,
        "results": [{"addr": "0x1100", "ok": False, "error": "bad type: expected ';'"}],
    }
    # An item is atomic: a failing type must not leave the rename half-applied.
    assert main.name == "main"
    assert main.comment == ""
    assert view.transactions == []


def test_annotate_many_rolls_back_when_the_core_fails_mid_apply() -> None:
    view = _annotate_view()
    _main, helper = view.functions
    helper.user_type_error = RuntimeError("core exploded")
    _, annotate = get_tool("rex_annotate_many")
    with pytest.raises(FakeToolError) as exc:
        annotate(
            FakeParsingToolCall(view),
            [
                {"addr": "0x1100", "name": "renamed"},
                {"addr": "0x2000", "prototype": "int helper(int)"},
            ],
        )
    assert exc.value.code == "annotate_failed"
    assert "core exploded" in exc.value.message
    # The fake records the revert marker; the real core reverts the whole batch inside
    # undoable_transaction, which is what the response's "rolled back" wording relies on.
    assert view.transactions == ["open", "revert"]


def test_annotate_many_rejects_oversized_or_mistyped_strings_per_item() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [
            {"addr": "0x1100", "name": ""},
            {"addr": "0x1100", "name": 7},
            {"addr": "0x1100", "name": "x" * (tools._MAX_ANNOTATE_NAME_CHARS + 1)},
            {"addr": "0x1100", "comment": 5},
            {"addr": "0x1100", "comment": "c" * (tools._MAX_ANNOTATE_COMMENT_CHARS + 1)},
            {"addr": "0x1100", "prototype": ""},
            {"addr": "0x1100", "prototype": "t" * (tools._MAX_ANNOTATE_PROTOTYPE_CHARS + 1)},
        ],
    )
    rows = result["results"]
    assert rows[0]["error"] == "name must be a non-empty string"
    assert rows[1]["error"] == "name must be a non-empty string"
    assert rows[2]["error"] == f"name exceeds {tools._MAX_ANNOTATE_NAME_CHARS} characters"
    assert rows[3]["error"] == "comment must be a string"
    assert rows[4]["error"] == f"comment exceeds {tools._MAX_ANNOTATE_COMMENT_CHARS} characters"
    assert rows[5]["error"] == "prototype must be a non-empty string"
    assert rows[6]["error"] == f"prototype exceeds {tools._MAX_ANNOTATE_PROTOTYPE_CHARS} characters"
    assert result["applied"] == 0
    assert result["failed"] == 7
    assert view.transactions == []


def test_annotate_many_accepts_strings_exactly_at_the_caps() -> None:
    view = _annotate_view()
    main, _helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [
            {
                "addr": "0x1100",
                "name": "n" * tools._MAX_ANNOTATE_NAME_CHARS,
                "comment": "c" * tools._MAX_ANNOTATE_COMMENT_CHARS,
                "prototype": "t" * tools._MAX_ANNOTATE_PROTOTYPE_CHARS,
            }
        ],
    )
    assert result["applied"] == 1
    assert result["failed"] == 0
    assert main.name == "n" * tools._MAX_ANNOTATE_NAME_CHARS
    assert main.comment == "c" * tools._MAX_ANNOTATE_COMMENT_CHARS
    assert main.user_type == "t" * tools._MAX_ANNOTATE_PROTOTYPE_CHARS


def test_annotate_many_collapses_repeated_items_onto_one_function_last_write_wins() -> None:
    view = _annotate_view()
    main, _helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    # Both items resolve to main (0x1150 is mid-function), so the second item's comment
    # overwrites the first: annotations are function-level and apply in item order.
    result = annotate(
        FakeParsingToolCall(view),
        [
            {"addr": "0x1150", "comment": "first"},
            {"addr": "0x1100", "comment": "second", "name": "final_name"},
        ],
    )
    assert result["applied"] == 2
    assert result["failed_count"] == 0
    assert result["total"] == 2
    assert main.comment == "second"
    assert main.name == "final_name"
    # One transaction: the collapsed items are still a single undo step.
    assert view.transactions == ["open", "commit"]


def test_annotate_batch_leaves_one_undo_entry_that_rex_undo_reverses() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    _, undo = get_tool("rex_undo")
    # The API documents undoable_transaction as creating an Undo state containing the
    # batch's actions, so the fake models the committed entry (helpers.py). This pins the
    # rex_undo docstring's one settled composition claim: one batch is one undo step and
    # rex_undo reverses it whole. The tag/metadata/type-library writes the API leaves
    # undocumented push nothing here, so the fake cannot pin those either way.
    annotate(FakeParsingToolCall(view), [{"addr": "0x1100", "name": "renamed"}])
    assert view.file.undo_entries == ["rex_annotate_many batch"]
    assert undo(_call(view)) == {"undone": True, "undo_left": 0, "redo_left": 1}
    assert view.file.undo_entries == []
    assert view.file.redo_entries == ["rex_annotate_many batch"]
    # A batch the core rolls back mid-apply commits nothing, so there is no entry to undo.
    rollback_view = _annotate_view()
    rollback_view.functions[1].user_type_error = RuntimeError("core exploded")
    with pytest.raises(FakeToolError):
        annotate(
            FakeParsingToolCall(rollback_view),
            [
                {"addr": "0x1100", "name": "renamed"},
                {"addr": "0x2000", "prototype": "int helper(int)"},
            ],
        )
    assert rollback_view.file.undo_entries == []


def test_annotate_many_lists_all_unknown_fields() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x1100", "hue": "blue", "tint": "warm"}],
    )
    assert result["results"] == [
        {"addr": "0x1100", "ok": False, "error": "unknown field(s): hue, tint"}
    ]


# --- rex_type_library_import ----------------------------------------------------------------


def _library_on_disk(tmp_path: Path, library: FakeTypeLibrary) -> str:
    path = str(tmp_path / "libc.bntl")
    TYPE_LIBRARIES_ON_DISK[path] = library
    return path


def test_type_library_import_attaches_and_imports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tools, "_EXPORT_ROOT", tmp_path / "exports")
    library = FakeTypeLibrary(name="libc")
    path = _library_on_disk(tmp_path, library)
    # "open" resolves to a deconflicted name because the view already has one; "bad" is
    # not provided by the library at all.
    view = FakeBinaryView(library_types={"open": "open_0", "bad": None})
    _, import_tool = get_tool("rex_type_library_import")
    result = import_tool(_call(view), path, ["open", "bad"])
    assert result == {
        "library": "libc",
        "imported": [{"requested": "open", "resolved": "open_0"}],
        "failed": [{"requested": "bad", "reason": "not provided by this type library"}],
        "applied": 1,
        "failed_count": 1,
        "total": 2,
    }
    # The library itself was attached to the view once, before any name was imported.
    assert view.type_libraries == [library]
    assert view.imported_library_types == [(library, "open"), (library, "bad")]


def test_type_library_import_reports_an_unnamed_library(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _library_on_disk(tmp_path, FakeTypeLibrary(name=None))
    view = FakeBinaryView(library_types={"open": "open"})
    _, import_tool = get_tool("rex_type_library_import")
    result = import_tool(_call(view), str(tmp_path / "libc.bntl"), ["open"])
    assert result["library"] is None
    assert result["imported"] == [{"requested": "open", "resolved": "open"}]


def test_type_library_import_reports_a_missing_library_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tools, "_EXPORT_ROOT", tmp_path / "exports")
    view = FakeBinaryView()
    _, import_tool = get_tool("rex_type_library_import")
    with pytest.raises(FakeToolError) as exc:
        import_tool(_call(view), str(tmp_path / "absent.bntl"), ["open"])
    assert exc.value.code == "library_not_found"
    # A path short enough to echo whole is echoed whole.
    assert exc.value.message == (f"could not load a type library from '{tmp_path / 'absent.bntl'}'")


def test_type_library_import_rejects_bad_names_lists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tools, "_EXPORT_ROOT", tmp_path / "exports")
    _library_on_disk(tmp_path, FakeTypeLibrary(name="libc"))
    view = FakeBinaryView()
    _, import_tool = get_tool("rex_type_library_import")
    long_name = "x" * (tools._MAX_TYPE_NAME_CHARS + 1)
    for names, message in (
        ("open", "names must be a list of type names"),
        ([], f"names must contain between 1 and {tools._MAX_TYPE_LIBRARY_NAMES} entries"),
        (
            ["a"] * (tools._MAX_TYPE_LIBRARY_NAMES + 1),
            f"names must contain between 1 and {tools._MAX_TYPE_LIBRARY_NAMES} entries",
        ),
        ([1], "names[0] must be a string type name"),
        ([""], "names[0] must not be empty"),
        ([long_name], f"names[0] exceeds {tools._MAX_TYPE_NAME_CHARS} characters"),
    ):
        with pytest.raises(FakeToolError) as exc:
            import_tool(_call(view), "/nowhere.bntl", names)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Exactly at both caps — 64 entries of exactly 255 characters each — the list is
    # accepted: the library loads, attaches, and every name reports as not provided.
    at_cap = ["n" * tools._MAX_TYPE_NAME_CHARS] * tools._MAX_TYPE_LIBRARY_NAMES
    at_cap_result = import_tool(_call(view), str(tmp_path / "libc.bntl"), at_cap)
    assert at_cap_result["total"] == tools._MAX_TYPE_LIBRARY_NAMES
    assert len(at_cap_result["failed"]) == tools._MAX_TYPE_LIBRARY_NAMES


# --- rex_type_library_export ----------------------------------------------------------------


def _typed_view() -> FakeBinaryView:
    return FakeBinaryView(
        arch=FakeArchitecture("x86_64"),
        types={
            "open": FakeType("open", "int open(char *path, int flags)"),
            "color": FakeType("color", "enum color { RED, GREEN }"),
        },
    )


def test_type_library_export_writes_types_to_a_bntl(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    view = _typed_view()
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["open", "color"], filename="recovered.bntl")
    assert result == {
        "path": str((root / "recovered.bntl").resolve()),
        "bytes_written": 4,
        "library": "recovered",
        "exported": ["open", "color"],
        "failed": [],
        "applied": 2,
        "failed_count": 0,
        "total": 2,
    }
    # The file holds exactly the bytes the (fake) core wrote, in the export root.
    assert (root / "recovered.bntl").read_bytes() == b"BNTL"
    library = view.exported_types[0][0]
    assert library.name == "recovered"
    assert library.arch is not None and library.arch.name == "x86_64"
    assert library.finalized is True
    assert [(name, type_obj) for _, name, type_obj in view.exported_types] == [
        ("open", view._types["open"]),
        ("color", view._types["color"]),
    ]


def test_type_library_export_objects_routes_through_the_object_exporter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _typed_view()
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["open"], kind="objects", filename="objs.bntl")
    assert result["exported"] == ["open"]
    assert view.exported_objects == [(view.exported_objects[0][0], "open", view._types["open"])]
    assert view.exported_types == []


def test_type_library_export_reports_missing_types(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _typed_view()
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["color", "absent"], filename="mixed.bntl")
    assert result["exported"] == ["color"]
    assert result["failed"] == [
        {"requested": "absent", "reason": "no type with this name in the view"}
    ]
    assert result["applied"] == 1
    assert result["failed_count"] == 1
    assert result["total"] == 2
    assert [name for _, name, _ in view.exported_types] == ["color"]


def test_type_library_export_requires_an_architecture() -> None:
    _, export = get_tool("rex_type_library_export")
    with pytest.raises(FakeToolError) as exc:
        export(_call(FakeBinaryView()), "recovered", ["open"], filename="x.bntl")
    assert exc.value.code == "no_arch"
    assert exc.value.message == ("the binary view has no architecture to create a type library for")


def test_type_library_export_reports_finalize_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    broken = FakeTypeLibrary(finalize_result=False)
    monkeypatch.setattr(FakeTypeLibrary, "new", staticmethod(lambda arch, name: broken))
    view = FakeBinaryView(arch=FakeArchitecture("x86_64"), types={"open": FakeType("open")})
    _, export = get_tool("rex_type_library_export")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), "recovered", ["open"], filename="x.bntl")
    assert exc.value.code == "finalize_failed"
    assert exc.value.message == "could not finalize type library 'recovered'"
    assert broken.written_paths == []


def test_type_library_export_reports_write_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    broken = FakeTypeLibrary(write_error=OSError("disk full"))
    monkeypatch.setattr(FakeTypeLibrary, "new", staticmethod(lambda arch, name: broken))
    view = FakeBinaryView(arch=FakeArchitecture("x86_64"), types={"open": FakeType("open")})
    _, export = get_tool("rex_type_library_export")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), "recovered", ["open"], filename="broken.bntl")
    assert exc.value.code == "export_failed"
    assert exc.value.message == "could not write export file: disk full"


def test_type_library_export_enforces_the_byte_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    blob = b"\x00" * 100
    library = FakeTypeLibrary(file_bytes=blob)
    monkeypatch.setattr(FakeTypeLibrary, "new", staticmethod(lambda arch, name: library))
    view = FakeBinaryView(arch=FakeArchitecture("x86_64"), types={"open": FakeType("open")})
    _, export = get_tool("rex_type_library_export")
    # Exactly at the cap the file stays: the boundary is inclusive.
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 100)
    result = export(_call(view), "recovered", ["open"], filename="exact.bntl")
    assert result["bytes_written"] == 100
    assert (root / "exact.bntl").read_bytes() == blob
    # One byte over the cap and the file is removed, not left behind oversized.
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 99)
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), "recovered", ["open"], filename="huge.bntl")
    assert exc.value.code == "export_failed"
    assert exc.value.message == (
        f"type library file exceeds the {tools._MAX_EXPORT_FILE_BYTES} byte export cap"
    )
    assert not (root / "huge.bntl").exists()


def test_type_library_export_rejects_invalid_inputs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _typed_view()
    _, export = get_tool("rex_type_library_export")
    for violation, message, code in (
        ({"library_name": ""}, "library_name must not be empty", "invalid_params"),
        (
            {"library_name": "x" * (tools._MAX_TYPE_NAME_CHARS + 1)},
            f"library_name exceeds {tools._MAX_TYPE_NAME_CHARS} characters",
            "library_name_too_large",
        ),
        ({"kind": "bogus"}, "kind must be 'types' or 'objects', not 'bogus'", "invalid_params"),
        (
            {"filename": "/abs/path.bntl"},
            "filename must be a plain file name, not an absolute path",
            "invalid_params",
        ),
        ({"filename": ""}, "filename must not be empty", "invalid_params"),
    ):
        arguments = {"library_name": "recovered", "filename": "x.bntl", **violation}
        with pytest.raises(FakeToolError) as exc:
            export(_call(view), arguments.pop("library_name"), ["open"], **arguments)
        assert exc.value.code == code
        assert exc.value.message == message
    # Validation happens before the library is created: nothing was attached or exported.
    assert view.exported_types == []


# --- rex_struct_from_access ------------------------------------------------------------------


def _struct_view(members: list[FakeStructureMember], width: int) -> FakeBinaryView:
    return FakeBinaryView(structure=FakeStructureType(members, width))


def test_struct_from_access_creates_and_defines_the_struct() -> None:
    members = [
        FakeStructureMember("field_0", 0, FakeType("field_0", "int32_t")),
        FakeStructureMember("ptr", 8, FakeType("ptr", "void *")),
    ]
    view = _struct_view(members, width=16)
    _, create = get_tool("rex_struct_from_access")
    result = create(_call(view), "ctx")
    assert result == {
        "name": "ctx",
        "registered": "ctx",
        "width": 16,
        "member_count": 2,
        "members": [
            {"offset": 0, "name": "field_0", "type": "int32_t"},
            {"offset": 8, "name": "ptr", "type": "void *"},
        ],
        "truncated": False,
    }
    # The struct is defined in the view under an auto type id derived from this tool's
    # source marker and the requested name.
    assert view.defined_types == [("auto:rex_struct:ctx", "ctx", view._structure)]


def test_struct_from_access_reports_a_deconflicted_registered_name() -> None:
    view = FakeBinaryView(
        structure=FakeStructureType([], 0),
        defined_type_name="ctx_0",
    )
    _, create = get_tool("rex_struct_from_access")
    result = create(_call(view), "ctx")
    assert result["registered"] == "ctx_0"
    assert result["member_count"] == 0


def test_struct_from_access_caps_the_echoed_members() -> None:
    exact = [
        FakeStructureMember(f"field_{offset}", offset, FakeType(f"field_{offset}"))
        for offset in range(tools._MAX_STRUCT_MEMBERS)
    ]
    view = _struct_view(exact, width=tools._MAX_STRUCT_MEMBERS)
    _, create = get_tool("rex_struct_from_access")
    at_cap = create(_call(view), "ctx")
    assert at_cap["member_count"] == tools._MAX_STRUCT_MEMBERS
    assert len(at_cap["members"]) == tools._MAX_STRUCT_MEMBERS
    assert at_cap["truncated"] is False

    one_more = exact + [FakeStructureMember("last", tools._MAX_STRUCT_MEMBERS, FakeType("last"))]
    over = create(_call(_struct_view(one_more, width=200)), "ctx")
    assert over["member_count"] == tools._MAX_STRUCT_MEMBERS + 1
    assert len(over["members"]) == tools._MAX_STRUCT_MEMBERS
    assert over["truncated"] is True


def test_struct_from_access_reports_the_core_refusal() -> None:
    view = FakeBinaryView()
    _, create = get_tool("rex_struct_from_access")
    with pytest.raises(FakeToolError) as exc:
        create(_call(view), "ctx")
    assert exc.value.code == "create_failed"
    assert exc.value.message == (
        "could not create a structure from offset accesses: "
        "BNCreateStructureFromOffsetAccess failed to create struct from offsets"
    )
    assert view.defined_types == []


def test_struct_from_access_rejects_bad_names() -> None:
    view = FakeBinaryView()
    _, create = get_tool("rex_struct_from_access")
    for name, message, code in (
        ("", "name must not be empty", "invalid_params"),
        (
            "x" * (tools._MAX_TYPE_NAME_CHARS + 1),
            f"name exceeds {tools._MAX_TYPE_NAME_CHARS} characters",
            "name_too_large",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            create(_call(view), name)
        assert exc.value.code == code
        assert exc.value.message == message
    # Exactly at the cap the name is accepted (with the fake struct in place).
    view_at_cap = _struct_view([], 0)
    at_cap = create(_call(view_at_cap), "x" * tools._MAX_TYPE_NAME_CHARS)
    assert at_cap["name"] == "x" * tools._MAX_TYPE_NAME_CHARS


# --- rex_derived_string_refs -----------------------------------------------------------


def _derived_view() -> FakeBinaryView:
    handler = FakeFunction("handler", 0x2000, 0x2100)
    main = FakeFunction("main", 0x1100, 0x1200)
    located = FakeDerivedString(
        "Enter license: ",
        FakeDerivedStringLocation("CodeStringLocation", 0x7FF0, 15),
        refs=[FakeReferenceSource(handler, 0x2010), FakeReferenceSource(main, 0x1150)],
    )
    bare = FakeDerivedString("stack-built {}", None, refs=[FakeReferenceSource(None, 0x3300)])
    return FakeBinaryView(derived_strings=[located, bare])


def test_derived_string_refs_lists_strings_and_code_refs() -> None:
    view = _derived_view()
    _, refs = get_tool("rex_derived_string_refs")
    result = refs(_call(view))
    assert result == {
        "total": 2,
        "truncated": False,
        "strings": [
            {
                "value": "Enter license: ",
                "location": {"type": "CodeStringLocation", "address": "0x7ff0", "length": 15},
                "refs": [
                    {
                        "function_start": "0x2000",
                        "function_name": "handler",
                        "address": "0x2010",
                    },
                    {"function_start": "0x1100", "function_name": "main", "address": "0x1150"},
                ],
                "refs_truncated": False,
            },
            {
                "value": "stack-built {}",
                "location": None,
                "refs": [{"function_start": None, "function_name": None, "address": "0x3300"}],
                "refs_truncated": False,
            },
        ],
    }
    # Pin: the core call is bounded by exactly the echo cap plus one, so a wider or
    # narrower bound than _MAX_DERIVED_STRING_REFS + 1 must update this pin deliberately.
    assert view.derived_code_ref_requests == [21, 21]


def test_derived_string_refs_filters_by_substring_regex_and_case() -> None:
    strings = [
        FakeDerivedString(
            "alpha one", FakeDerivedStringLocation("DataBackedStringLocation", 0x10, 9)
        ),
        FakeDerivedString("beta two", None),
        FakeDerivedString("ALPHA three", None),
    ]
    view = FakeBinaryView(derived_strings=strings)
    _, refs = get_tool("rex_derived_string_refs")
    assert refs(_call(view), pattern="alpha")["total"] == 1
    assert refs(_call(view), pattern="alpha", ignore_case=True)["total"] == 2
    # "alpha (one|three)" is only matchable in regex mode: substring search finds neither.
    assert refs(_call(view), pattern=r"alpha (one|three)", regex=True)["total"] == 1
    assert (
        refs(_call(view), pattern=r"alpha (one|three)", regex=True, ignore_case=True)["total"] == 2
    )
    empty = refs(_call(view), pattern="nomatch")
    assert empty == {"total": 0, "truncated": False, "strings": []}


def test_derived_string_refs_paginates_with_exact_total() -> None:
    strings = [FakeDerivedString(f"s{i}", None) for i in range(3)]
    view = FakeBinaryView(derived_strings=strings)
    _, refs = get_tool("rex_derived_string_refs")
    paged = refs(_call(view), limit=1, offset=1)
    assert paged["total"] == 3
    assert paged["truncated"] is True
    assert [entry["value"] for entry in paged["strings"]] == ["s1"]
    tail = refs(_call(view), limit=1, offset=2)
    assert tail["truncated"] is False
    assert [entry["value"] for entry in tail["strings"]] == ["s2"]


def test_derived_string_refs_caps_refs_per_string() -> None:
    filler = FakeFunction("filler", 0x9000, 0x9100)
    capped = FakeDerivedString(
        "big", None, refs=[FakeReferenceSource(filler, 0x9000 + index) for index in range(23)]
    )
    exact = FakeDerivedString(
        "exact", None, refs=[FakeReferenceSource(filler, 0x9000 + index) for index in range(20)]
    )
    view = FakeBinaryView(derived_strings=[capped, exact])
    _, refs = get_tool("rex_derived_string_refs")
    entries = refs(_call(view))["strings"]
    assert len(entries[0]["refs"]) == 20
    assert entries[0]["refs"][-1]["address"] == "0x9013"
    assert entries[0]["refs_truncated"] is True
    # Exactly at the cap the flag stays False: the cap is a bound, not an off-by-one hint.
    assert entries[1]["refs_truncated"] is False


def test_derived_string_refs_defaults_to_a_bounded_page() -> None:
    strings = [FakeDerivedString(f"s{i}", None) for i in range(25)]
    view = FakeBinaryView(derived_strings=strings)
    _, refs = get_tool("rex_derived_string_refs")
    result = refs(_call(view))
    assert len(result["strings"]) == 20
    assert result["truncated"] is True
    # Like the other sweep tools, total counts only what was seen: exact when the page
    # is not truncated, otherwise the first item past the window.
    assert result["total"] == 21
    complete = refs(_call(view), limit=25)
    assert complete["total"] == 25
    assert complete["truncated"] is False


def test_derived_string_refs_truncates_long_values() -> None:
    view = FakeBinaryView(derived_strings=[FakeDerivedString("x" * 600, None)])
    _, refs = get_tool("rex_derived_string_refs")
    value = refs(_call(view))["strings"][0]["value"]
    assert value == "x" * tools._MAX_CHARS + f"... [{600 - tools._MAX_CHARS} chars truncated]"


def test_derived_string_refs_rejects_out_of_range_windows() -> None:
    view = FakeBinaryView(derived_strings=[FakeDerivedString("s", None)])
    _, refs = get_tool("rex_derived_string_refs")
    for kwargs, message in (
        ({"limit": -1}, "Invalid integer parameter 'limit': Must be at least 0"),
        (
            {"limit": tools._MAX_LIMIT + 1},
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}",
        ),
        ({"offset": -1}, "Invalid integer parameter 'offset': Must be at least 0"),
    ):
        with pytest.raises(FakeToolError) as exc:
            refs(_call(view), **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    assert refs(_call(view), limit=tools._MAX_LIMIT)["total"] == 1


# --- rex_component_get / rex_component_create / rex_component_add_functions ------------


def _component_view() -> FakeBinaryView:
    crypto = FakeFunction("crypto_mix", 0x3000, 0x3100)
    parse = FakeFunction("parse_header", 0x1000, 0x1100)
    root_fn = FakeFunction("root_fn", 0x5000, 0x5100)
    net = FakeComponent("Network", "guid-net", functions=[crypto])
    net.children.append(FakeComponent("Crypto", "guid-crypto", functions=[parse]))
    return FakeBinaryView(
        functions=[crypto, parse, root_fn],
        component_root=FakeComponent("__root__", "guid-root", children=[net], functions=[root_fn]),
    )


def test_component_get_reports_root_and_nested_members() -> None:
    view = _component_view()
    _, get = get_tool("rex_component_get")
    root = get(_call(view), "/")
    assert root["guid"] == "guid-root"
    assert root["parent_path"] is None
    assert root["children"] == [{"path": "/Network", "display_name": "Network", "guid": "guid-net"}]
    assert root["functions"] == [{"start": "0x5000", "name": "root_fn"}]
    # The root resolves through the verified root_component property, never through the
    # "/" pathname lookup the installed API does not document.
    assert view.component_path_lookups == []

    network = get(_call(view), "/Network")
    assert network["parent_path"] == "/"
    assert network["display_name"] == "Network"
    assert network["children"] == [
        {"path": "/Network/Crypto", "display_name": "Crypto", "guid": "guid-crypto"}
    ]
    assert network["functions"] == [{"start": "0x3000", "name": "crypto_mix"}]

    crypto = get(_call(view), "/Network/Crypto")
    assert crypto["parent_path"] == "/Network"
    assert crypto["children"] == []
    assert crypto["functions"] == [{"start": "0x1000", "name": "parse_header"}]


def test_component_get_sorts_functions_and_paginates() -> None:
    view = _component_view()
    first = FakeFunction("zzz", 0x8300, 0x8400)
    second = FakeFunction("aaa", 0x8100, 0x8200)
    third = FakeFunction("mmm", 0x8200, 0x8300)
    view.root_component.children.append(
        FakeComponent("Shuffled", "guid-shuffled", functions=[first, second, third])
    )
    _, get = get_tool("rex_component_get")
    result = get(_call(view), "/Shuffled")
    assert [entry["name"] for entry in result["functions"]] == ["aaa", "mmm", "zzz"]
    assert result["function_count"] == 3
    assert result["truncated"] is False
    paged = get(_call(view), "/Shuffled", limit=1, offset=1)
    assert [entry["name"] for entry in paged["functions"]] == ["mmm"]
    assert paged["function_count"] == 3
    assert paged["truncated"] is True
    tail = get(_call(view), "/Shuffled", limit=1, offset=2)
    assert tail["truncated"] is False
    assert [entry["name"] for entry in tail["functions"]] == ["zzz"]
    empty = get(_call(view), "/Shuffled", limit=0)
    assert empty["functions"] == []
    assert empty["truncated"] is True


def test_component_get_defaults_to_a_bounded_function_page() -> None:
    functions = [FakeFunction(f"f{i}", 0x1000 + 4 * i, 0x1100 + 4 * i) for i in range(101)]
    hub = FakeComponent("Hub", "guid-hub", functions=functions)
    view = FakeBinaryView(component_root=FakeComponent("__root__", "guid-root", children=[hub]))
    _, get = get_tool("rex_component_get")
    result = get(_call(view), "/Hub")
    assert len(result["functions"]) == 100
    assert result["functions"][-1]["start"] == "0x118c"
    assert result["function_count"] == 101
    assert result["truncated"] is True


def test_component_get_caps_children() -> None:
    overflow = FakeComponent(
        "Hub", "guid-hub", children=[FakeComponent(f"k{i}", f"guid-k{i}") for i in range(201)]
    )
    view = FakeBinaryView(
        component_root=FakeComponent("__root__", "guid-root", children=[overflow])
    )
    _, get = get_tool("rex_component_get")
    result = get(_call(view), "/Hub")
    assert len(result["children"]) == 200
    assert result["children"][-1]["path"] == "/Hub/k199"
    assert result["children_truncated"] is True


def test_component_get_children_at_the_cap_are_not_truncated() -> None:
    exact = FakeComponent(
        "Hub", "guid-hub", children=[FakeComponent(f"k{i}", f"guid-k{i}") for i in range(200)]
    )
    view = FakeBinaryView(component_root=FakeComponent("__root__", "guid-root", children=[exact]))
    _, get = get_tool("rex_component_get")
    assert get(_call(view), "/Hub")["children_truncated"] is False


def test_component_get_rejects_bad_paths_and_reports_missing() -> None:
    view = _component_view()
    _, get = get_tool("rex_component_get")
    for path, message in (
        ("", "path must not be empty"),
        ("Network", "path must be an absolute path starting with '/'"),
        ("/Network/", "path must not end with '/'"),
        ("/Network//Crypto", "path must not contain empty path segments"),
        ("x" * 513, "path exceeds 512 characters"),
    ):
        with pytest.raises(FakeToolError) as exc:
            get(_call(view), path)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # At the length cap the path still goes to the lookup and misses cleanly.
    with pytest.raises(FakeToolError) as exc:
        get(_call(view), "/" + "x" * 511)
    assert exc.value.code == "component_not_found"
    assert exc.value.message.startswith("no component at path '/")


def test_component_create_nests_and_reports_canonical_paths() -> None:
    view = _component_view()
    _, create = get_tool("rex_component_create")
    top = create(_call(view), "Crypto")
    assert top == {"path": "/Crypto", "display_name": "Crypto", "guid": "guid-1"}
    nested = create(_call(view), "Symmetric", "/Crypto")
    assert nested == {"path": "/Crypto/Symmetric", "display_name": "Symmetric", "guid": "guid-2"}
    under_root = create(_call(view), "Solver", "/")
    assert under_root == {"path": "/Solver", "display_name": "Solver", "guid": "guid-3"}
    resolved = view.get_component_by_path("/Crypto/Symmetric")
    assert resolved is not None and resolved.guid == "guid-2"


def test_component_create_reports_the_core_suffix_for_duplicate_names() -> None:
    view = _component_view()
    _, create = get_tool("rex_component_create")
    create(_call(view), "Crypto")
    duplicate = create(_call(view), "Crypto")
    assert duplicate["display_name"] == "Crypto (1)"
    assert duplicate["path"] == "/Crypto (1)"


def test_component_create_validates_name_and_parent() -> None:
    view = _component_view()
    _, create = get_tool("rex_component_create")
    for kwargs, message, code in (
        ({"name": ""}, "name must not be empty", "invalid_params"),
        ({"name": "a/b"}, "name must not contain '/'", "invalid_params"),
        ({"name": "x" * 129}, "name exceeds 128 characters", "name_too_large"),
        (
            {"name": "ok", "parent_path": "Network"},
            "parent_path must be an absolute path starting with '/'",
            "invalid_params",
        ),
        (
            {"name": "ok", "parent_path": "/Network/"},
            "parent_path must not end with '/'",
            "invalid_params",
        ),
        (
            {"name": "ok", "parent_path": "/Network//Crypto"},
            "parent_path must not contain empty path segments",
            "invalid_params",
        ),
        (
            {"name": "ok", "parent_path": "y" * 513},
            "parent_path exceeds 512 characters",
            "invalid_params",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            create(_call(view), **kwargs)
        assert exc.value.code == code
        assert exc.value.message == message
    with pytest.raises(FakeToolError) as exc:
        create(_call(view), "ok", "/Missing")
    assert exc.value.code == "component_not_found"
    # At the name cap creation still works, and an empty parent_path means top level.
    assert create(_call(view), "x" * 128)["display_name"] == "x" * 128
    assert create(_call(view), "atcap", "")["path"] == "/atcap"


def test_component_add_functions_resolves_then_adds() -> None:
    view = _component_view()
    _, add = get_tool("rex_component_add_functions")
    result = add(FakeParsingToolCall(view), "/Network", ["0x3000", "0x5000"])
    assert result["path"] == "/Network"
    assert result["added_count"] == 2
    # The uniform batch-summary keys, shared with rex_annotate_many and the type-library
    # tools so a caller reads the same failed summary from every batch response.
    assert result["applied"] == 2
    assert result["failed_count"] == 0
    assert result["total"] == 2
    assert result["results"] == [
        {"start": "0x3000", "name": "crypto_mix", "added": True},
        {"start": "0x5000", "name": "root_fn", "added": True},
    ]
    added_names = [function.name for function in view.root_component.children[0].added_functions]
    assert added_names == ["crypto_mix", "root_fn"]


def test_component_add_functions_is_all_or_nothing() -> None:
    view = _component_view()
    _, add = get_tool("rex_component_add_functions")
    network = view.root_component.children[0]
    with pytest.raises(FakeToolError) as exc:
        add(FakeParsingToolCall(view), "/Network", ["0x3000", "0x9999"])
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "no analyzed function contains 0x9999"
    assert network.added_functions == []


def test_component_add_functions_reports_declined_adds() -> None:
    view = _component_view()
    network = view.root_component.children[0]
    network.rejected_functions.append(view.functions[1])
    _, add = get_tool("rex_component_add_functions")
    result = add(FakeParsingToolCall(view), "/Network", ["0x1000"])
    assert result["added_count"] == 0
    assert result["applied"] == 0
    assert result["failed_count"] == 1
    assert result["total"] == 1
    assert result["results"] == [{"start": "0x1000", "name": "parse_header", "added": False}]


def test_component_add_functions_into_the_root_component() -> None:
    view = _component_view()
    _, add = get_tool("rex_component_add_functions")
    result = add(FakeParsingToolCall(view), "/", ["0x3000"])
    assert result == {
        "path": "/",
        "added_count": 1,
        "applied": 1,
        "failed_count": 0,
        "total": 1,
        "results": [{"start": "0x3000", "name": "crypto_mix", "added": True}],
    }
    assert len(view.root_component.added_functions) == 1
    assert view.component_path_lookups == []


def test_component_add_functions_validates_inputs() -> None:
    view = _component_view()
    _, add = get_tool("rex_component_add_functions")
    for kwargs, message in (
        (
            {"path": "Network", "functions": ["0x3000"]},
            "path must be an absolute path starting with '/'",
        ),
        (
            {"path": "/Network", "functions": []},
            "functions must contain between 1 and 64 address expressions",
        ),
        (
            {"path": "/Network", "functions": ["0x3000"] * 65},
            "functions must contain between 1 and 64 address expressions",
        ),
        (
            {"path": "/Network", "functions": [7]},
            "functions[0] must be a string address expression",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            add(_call(view), **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    with pytest.raises(FakeToolError) as exc:
        add(_call(view), "/Network", "0x3000")
    assert exc.value.message == "functions must be a list of address expressions"
    with pytest.raises(FakeToolError) as exc:
        add(FakeParsingToolCall(view), "/Network", ["@@@"])
    assert exc.value.code == "invalid_params"
    assert "bad address expression" in exc.value.message
    # At the batch cap the call still goes through.
    at_cap = add(FakeParsingToolCall(view), "/Network", ["0x3000"] * 64)
    assert at_cap["added_count"] == 64


def test_report_show_renders_the_markdown_report() -> None:
    view = FakeBinaryView()
    _, show = get_tool("rex_report_show")
    markdown = "# Triage\n\n- `main` at 0x1100: recv-then-stack-copy\n[binaryninja://?expr=main]\n"
    result = show(_call(view), title="Triage report", markdown=markdown)
    # The markdown goes to the core whole; the markdown itself doubles as the plaintext
    # fallback, so command-line hosts render the same report instead of nothing.
    assert view.shown_reports == [("Triage report", markdown, markdown)]
    assert result == {
        "title": "Triage report",
        "length": len(markdown),
        "preview": markdown,
        "truncated": False,
    }


def test_report_show_truncates_only_the_echoed_preview() -> None:
    view = FakeBinaryView()
    _, show = get_tool("rex_report_show")
    markdown = "a" * (tools._MAX_CHARS + 88)
    result = show(_call(view), title="r", markdown=markdown)
    assert view.shown_reports == [("r", markdown, markdown)]
    assert result["preview"] == "a" * tools._MAX_CHARS + "... [88 chars truncated]"
    assert result["truncated"] is True
    assert result["length"] == len(markdown)


def test_report_show_rejects_oversized_markdown_without_rendering() -> None:
    view = FakeBinaryView()
    _, show = get_tool("rex_report_show")
    with pytest.raises(FakeToolError) as exc:
        show(_call(view), title="r", markdown="x" * (tools._MAX_REPORT_CONTENT_CHARS + 1))
    assert exc.value.code == "content_too_large"
    assert exc.value.message == f"markdown exceeds {tools._MAX_REPORT_CONTENT_CHARS} characters"
    assert view.shown_reports == []


def test_report_show_rejects_oversized_title_without_rendering() -> None:
    view = FakeBinaryView()
    _, show = get_tool("rex_report_show")
    with pytest.raises(FakeToolError) as exc:
        show(_call(view), title="t" * (tools._MAX_REPORT_TITLE_CHARS + 1), markdown="m")
    assert exc.value.code == "title_too_large"
    assert exc.value.message == f"title exceeds {tools._MAX_REPORT_TITLE_CHARS} characters"
    assert view.shown_reports == []


def test_report_show_honors_both_caps_exactly() -> None:
    view = FakeBinaryView()
    _, show = get_tool("rex_report_show")
    title = "t" * tools._MAX_REPORT_TITLE_CHARS
    markdown = "m" * tools._MAX_REPORT_CONTENT_CHARS
    result = show(_call(view), title=title, markdown=markdown)
    assert view.shown_reports == [(title, markdown, markdown)]
    assert result["length"] == tools._MAX_REPORT_CONTENT_CHARS
    assert result["truncated"] is True


def test_report_show_rejects_empty_title_and_markdown() -> None:
    view = FakeBinaryView()
    _, show = get_tool("rex_report_show")
    for kwargs, parameter in (
        ({"title": "", "markdown": "m"}, "title"),
        ({"title": "t", "markdown": ""}, "markdown"),
    ):
        with pytest.raises(FakeToolError) as exc:
            show(_call(view), **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == f"{parameter} must not be empty"
    assert view.shown_reports == []


def test_report_show_is_read_only() -> None:
    options, _ = get_tool("rex_report_show")
    assert options == {"read_only": True}
