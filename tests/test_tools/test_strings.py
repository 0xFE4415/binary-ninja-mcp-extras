from __future__ import annotations

from typing import Any, override

import pytest
from helpers import (
    FakeToolError,
    _call,
    get_tool,
)
from helpers_invoke import invoke_tool
from helpers_view import (
    FakeBinaryView,
    FakeDerivedString,
    FakeDerivedStringLocation,
    FakeFunction,
    FakeReferenceSource,
    FakeStringReference,
)

from binja_plugin import tools
from binja_plugin.tools import strings


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
        invoke_tool(search, _call(view), limit=tools._MAX_LIMIT + 1)
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
    assert exc.value.message == (
        "Invalid regular expression parameter 'pattern': missing ), unterminated subpattern"
        " at position 0"
    )
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), section="s" * 1000)
    assert exc.value.code == "section_not_found"
    assert "chars truncated]" in exc.value.message
    with pytest.raises(FakeToolError) as exc:
        invoke_tool(search, _call(view), limit=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    with pytest.raises(FakeToolError) as exc:
        invoke_tool(search, _call(view), limit=tools._MAX_LIMIT + 1)
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


@pytest.mark.parametrize("tool_name", ["rex_string_search", "rex_string_refs"])
@pytest.mark.parametrize("ignore_case", [False, True])
def test_string_tools_name_the_pattern_parameter_in_an_invalid_regex(
    tool_name: str, ignore_case: bool
) -> None:
    _, tool = get_tool(tool_name)
    with pytest.raises(FakeToolError) as exc:
        tool(_call(FakeBinaryView()), pattern="[", regex=True, ignore_case=ignore_case)
    assert exc.value.code == "invalid_regex"
    assert exc.value.message == (
        "Invalid regular expression parameter 'pattern': unterminated character set at position 0"
    )


@pytest.mark.parametrize("tool_name", ["rex_string_search", "rex_string_refs"])
def test_string_tools_accept_an_invalid_regex_as_a_plain_substring(tool_name: str) -> None:
    _, tool = get_tool(tool_name)
    assert tool(_call(FakeBinaryView()), pattern="[", regex=False)["strings"] == []


def test_string_search_reports_an_invalid_regex_before_a_missing_section() -> None:
    _, search = get_tool("rex_string_search")
    with pytest.raises(FakeToolError) as exc:
        search(_call(FakeBinaryView()), pattern="(", regex=True, section="nope")
    assert exc.value.code == "invalid_regex"


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
    capped = read(_call(view), 0x1100, max_chars=strings._MAX_STRING_READ_CHARS)
    assert capped["truncated"] is True
    assert len(capped["value"]) == strings._MAX_STRING_READ_CHARS + len("... [904 chars truncated]")
    short = FakeBinaryView(strings=[FakeStringReference("hi", 0x1100)])
    assert read(_call(short), 0x1100)["truncated"] is False
    with pytest.raises(FakeToolError) as exc:
        read(_call(view), 0x3000)
    assert exc.value.code == "no_string"


def test_string_search_rejects_negative_offset() -> None:
    view = FakeBinaryView(
        strings=[FakeStringReference("alpha", 0x100), FakeStringReference("alphabeta", 0x120)]
    )
    _, search = get_tool("rex_string_search")
    with pytest.raises(FakeToolError) as exc:
        invoke_tool(search, _call(view), pattern="alpha", limit=1, offset=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"
    # Nothing ran: the rejection happens before the scan.
    assert search(_call(view), pattern="alpha", limit=1, offset=0)["total"] == 2


def test_string_read_at_rejects_out_of_range_max_chars() -> None:
    view = FakeBinaryView(strings=[FakeStringReference("hello", 0x1100)])
    _, read = get_tool("rex_string_read_at")
    # max_chars below 1 is invalid on its face: rejected, never clamped to 1.
    for max_chars in (-5, 0):
        with pytest.raises(FakeToolError) as exc:
            invoke_tool(read, _call(view), 0x1100, max_chars=max_chars)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == "Invalid integer parameter 'max_chars': Must be at least 1"
    with pytest.raises(FakeToolError) as exc:
        invoke_tool(read, _call(view), 0x1100, max_chars=strings._MAX_STRING_READ_CHARS + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'max_chars': Must be at most {strings._MAX_STRING_READ_CHARS}"
    )
    # Both bounds are inclusive: exactly 1 and exactly the cap are accepted.
    at_minimum = read(_call(view), 0x1100, max_chars=1)
    assert at_minimum["value"] == "h... [4 chars truncated]"
    assert at_minimum["truncated"] is True


# --- rex_string_refs -------------------------------------------------------------------
def _mixed_view() -> FakeBinaryView:
    handler = FakeFunction("handler", 0x2000, 0x2100)
    main = FakeFunction("main", 0x1100, 0x1200)
    located = FakeDerivedString(
        "Enter license: ",
        FakeDerivedStringLocation("CodeStringLocation", 0x7FF0, 15),
        refs=[FakeReferenceSource(handler, 0x2010), FakeReferenceSource(main, 0x1150)],
    )
    bare = FakeDerivedString("stack-built {}", None, refs=[FakeReferenceSource(None, 0x3300)])
    return FakeBinaryView(
        strings=[FakeStringReference("usage: tool [-v]", 0x4000)],
        code_refs={0x4000: [FakeReferenceSource(main, 0x1150)]},
        derived_strings=[located, bare],
    )


def test_string_refs_returns_refs_to_ordinary_strings() -> None:
    # A binary with ordinary detected strings and code refs into them: the core case
    # the derived-strings-only predecessor never saw.
    view = FakeBinaryView(
        strings=[FakeStringReference("usage: tool [-v]", 0x4000)],
        code_refs={0x4000: [FakeReferenceSource(FakeFunction("main", 0x1100, 0x1200), 0x1150)]},
    )
    _, refs = get_tool("rex_string_refs")
    result = refs(_call(view))
    assert result == {
        "total": 1,
        "truncated": False,
        "strings": [
            {
                "value": "usage: tool [-v]",
                "location": {"type": "AsciiString", "address": "0x4000", "length": 16},
                "derived": False,
                "refs": [
                    {"function_start": "0x1100", "function_name": "main", "address": "0x1150"}
                ],
                "refs_truncated": False,
            }
        ],
    }
    # Pin: the core call is bounded by exactly the echo cap plus one, so a wider or
    # narrower bound than _MAX_STRING_REFS + 1 must update this pin deliberately.
    assert view.code_ref_requests == [(0x4000, 65)]


def test_string_refs_lists_ordinary_then_derived_strings() -> None:
    view = _mixed_view()
    _, refs = get_tool("rex_string_refs")
    result = refs(_call(view))
    assert [entry["derived"] for entry in result["strings"]] == [False, True, True]
    assert result["total"] == 3
    assert result["strings"][1:] == [
        {
            "value": "Enter license: ",
            "location": {"type": "CodeStringLocation", "address": "0x7ff0", "length": 15},
            "derived": True,
            "refs": [
                {"function_start": "0x2000", "function_name": "handler", "address": "0x2010"},
                {"function_start": "0x1100", "function_name": "main", "address": "0x1150"},
            ],
            "refs_truncated": False,
        },
        {
            "value": "stack-built {}",
            "location": None,
            "derived": True,
            "refs": [{"function_start": None, "function_name": None, "address": "0x3300"}],
            "refs_truncated": False,
        },
    ]
    assert view.derived_code_ref_requests == [65, 65]


def test_string_refs_filters_by_substring_regex_and_case() -> None:
    view = FakeBinaryView(
        strings=[FakeStringReference("alpha one", 0x10)],
        derived_strings=[
            FakeDerivedString("beta two", None),
            FakeDerivedString("ALPHA three", None),
        ],
    )
    _, refs = get_tool("rex_string_refs")
    assert refs(_call(view), pattern="alpha")["total"] == 1
    assert refs(_call(view), pattern="alpha", ignore_case=True)["total"] == 2
    # "alpha (one|three)" is only matchable in regex mode: substring search finds neither.
    assert refs(_call(view), pattern=r"alpha (one|three)", regex=True)["total"] == 1
    assert (
        refs(_call(view), pattern=r"alpha (one|three)", regex=True, ignore_case=True)["total"] == 2
    )
    empty = refs(_call(view), pattern="nomatch")
    assert empty == {"total": 0, "truncated": False, "strings": []}


def test_string_refs_paginates_with_exact_total() -> None:
    strings = [FakeStringReference(f"s{i}", 0x100 + i * 0x10) for i in range(3)]
    view = FakeBinaryView(strings=strings)
    _, refs = get_tool("rex_string_refs")
    paged = refs(_call(view), limit=1, offset=1)
    assert paged["total"] == 3
    assert paged["truncated"] is True
    assert [entry["value"] for entry in paged["strings"]] == ["s1"]
    tail = refs(_call(view), limit=1, offset=2)
    assert tail["truncated"] is False
    assert [entry["value"] for entry in tail["strings"]] == ["s2"]


def test_string_refs_caps_refs_per_string() -> None:
    filler = FakeFunction("filler", 0x9000, 0x9100)
    view = FakeBinaryView(
        strings=[FakeStringReference("big", 0x8000), FakeStringReference("exact", 0x8100)],
        code_refs={
            0x8000: [FakeReferenceSource(filler, 0x9000 + index) for index in range(65)],
            0x8100: [FakeReferenceSource(filler, 0x9000 + index) for index in range(64)],
        },
    )
    _, refs = get_tool("rex_string_refs")
    entries = refs(_call(view))["strings"]
    assert len(entries[0]["refs"]) == 64
    assert entries[0]["refs"][-1]["address"] == "0x903f"
    assert entries[0]["refs_truncated"] is True
    # Exactly at the cap the flag stays False: the cap is a bound, not an off-by-one hint.
    assert entries[1]["refs_truncated"] is False


def test_string_refs_caps_derived_refs_per_string() -> None:
    filler = FakeFunction("filler", 0x9000, 0x9100)
    capped = FakeDerivedString(
        "big", None, refs=[FakeReferenceSource(filler, 0x9000 + index) for index in range(65)]
    )
    exact = FakeDerivedString(
        "exact", None, refs=[FakeReferenceSource(filler, 0x9000 + index) for index in range(64)]
    )
    view = FakeBinaryView(derived_strings=[capped, exact])
    _, refs = get_tool("rex_string_refs")
    entries = refs(_call(view))["strings"]
    assert len(entries[0]["refs"]) == 64
    assert entries[0]["refs"][-1]["address"] == "0x903f"
    assert entries[0]["refs_truncated"] is True
    # Exactly at the cap the flag stays False: the cap is a bound, not an off-by-one hint.
    assert entries[1]["refs_truncated"] is False


def test_string_refs_defaults_to_a_bounded_page() -> None:
    strings = [FakeStringReference(f"s{i}", 0x100 + i * 0x10) for i in range(25)]
    view = FakeBinaryView(strings=strings)
    _, refs = get_tool("rex_string_refs")
    result = refs(_call(view))
    assert len(result["strings"]) == 20
    assert result["truncated"] is True
    # Like the other sweep tools, total counts only what was seen: exact when the page
    # is not truncated, otherwise the first item past the window.
    assert result["total"] == 21
    complete = refs(_call(view), limit=25)
    assert complete["total"] == 25
    assert complete["truncated"] is False


def test_string_refs_truncates_long_values() -> None:
    view = FakeBinaryView(strings=[FakeStringReference("x" * 600, 0x100)])
    _, refs = get_tool("rex_string_refs")
    value = refs(_call(view))["strings"][0]["value"]
    assert value == "x" * tools._MAX_CHARS + f"... [{600 - tools._MAX_CHARS} chars truncated]"


def test_string_refs_rejects_out_of_range_windows() -> None:
    view = FakeBinaryView(strings=[FakeStringReference("s", 0x100)])
    _, refs = get_tool("rex_string_refs")
    for kwargs, message in (
        ({"limit": -1}, "Invalid integer parameter 'limit': Must be at least 0"),
        (
            {"limit": tools._MAX_LIMIT + 1},
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}",
        ),
        ({"offset": -1}, "Invalid integer parameter 'offset': Must be at least 0"),
    ):
        with pytest.raises(FakeToolError) as exc:
            invoke_tool(refs, _call(view), **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    assert refs(_call(view), limit=tools._MAX_LIMIT)["total"] == 1


# --- rex_string_read_at fallback ----------------------------------------------------------
def test_string_read_at_marks_detected_strings() -> None:
    view = FakeBinaryView(strings=[FakeStringReference("hello", 0x1100)])
    _, read = get_tool("rex_string_read_at")
    assert read(_call(view), 0x1100) == {
        "address": "0x1100",
        "length": 5,
        "type": "AsciiString",
        "value": "hello",
        "truncated": False,
        "detected": True,
    }


def test_string_read_at_falls_back_to_a_nul_terminated_ascii_string() -> None:
    view = FakeBinaryView(memory={0x2000: b"abc\x00zzz\x00"})
    _, read = get_tool("rex_string_read_at")
    assert read(_call(view), 0x2000) == {
        "address": "0x2000",
        "length": 3,
        "type": "AsciiString",
        "value": "abc",
        "truncated": False,
        "detected": False,
    }
    assert read(_call(view), 0x2001)["value"] == "bc"


def test_string_read_at_fallback_accepts_exactly_max_chars() -> None:
    view = FakeBinaryView(memory={0x2000: b"abcd\x00"})
    _, read = get_tool("rex_string_read_at")
    result = read(_call(view), 0x2000, max_chars=4)
    assert result["value"] == "abcd"
    assert result["length"] == 4
    assert result["truncated"] is False
    assert result["detected"] is False


def test_string_read_at_fallback_bounds_a_long_read_and_flags_truncation() -> None:
    view = FakeBinaryView(memory={0x2000: b"abcdef\x00"})
    _, read = get_tool("rex_string_read_at")
    assert read(_call(view), 0x2000, max_chars=4) == {
        "address": "0x2000",
        "length": 4,
        "type": "AsciiString",
        "value": "abcd",
        "truncated": True,
        "detected": False,
    }


def test_string_read_at_fallback_rejects_unterminated_short_runs() -> None:
    view = FakeBinaryView(memory={0x2000: b"abc\xff"})
    _, read = get_tool("rex_string_read_at")
    with pytest.raises(FakeToolError) as exc:
        read(_call(view), 0x2000)
    assert exc.value.code == "no_string"


def test_string_read_at_reports_no_string_with_the_next_step() -> None:
    view = FakeBinaryView(memory={0x2000: b"\x00abc"})
    _, read = get_tool("rex_string_read_at")
    with pytest.raises(FakeToolError) as exc:
        read(_call(view), 0x2000)
    assert exc.value.code == "no_string"
    assert exc.value.message == (
        "no string at 0x2000: none detected and no NUL-terminated ASCII text there; "
        "rex_data_read reads raw bytes and rex_string_search lists detected strings"
    )


# --- rex_string_refs only_referenced ------------------------------------------------------
def _referenced_view() -> FakeBinaryView:
    main = FakeFunction("main", 0x1100, 0x1200)
    return FakeBinaryView(
        strings=[
            FakeStringReference("bare0", 0x4000),
            FakeStringReference("used1", 0x4010),
            FakeStringReference("bare2", 0x4020),
            FakeStringReference("used3", 0x4030),
        ],
        code_refs={
            0x4010: [FakeReferenceSource(main, 0x1150)],
            0x4030: [FakeReferenceSource(main, 0x1160)],
        },
        derived_strings=[
            FakeDerivedString("derived-bare", None),
            FakeDerivedString("derived-used", None, refs=[FakeReferenceSource(main, 0x1170)]),
        ],
    )


def test_string_refs_only_referenced_skips_unreferenced_strings() -> None:
    _, refs = get_tool("rex_string_refs")
    result = refs(_call(_referenced_view()), only_referenced=True)
    assert [entry["value"] for entry in result["strings"]] == ["used1", "used3", "derived-used"]
    assert result["total"] == 3
    assert result["truncated"] is False
    default = refs(_call(_referenced_view()))
    assert [entry["value"] for entry in default["strings"]][:2] == ["bare0", "used1"]
    assert default["total"] == 6


def test_string_refs_only_referenced_pages_over_referenced_strings_only() -> None:
    _, refs = get_tool("rex_string_refs")
    first = refs(_call(_referenced_view()), only_referenced=True, limit=1)
    assert [entry["value"] for entry in first["strings"]] == ["used1"]
    assert first["total"] == 2
    assert first["truncated"] is True
    second = refs(_call(_referenced_view()), only_referenced=True, limit=1, offset=1)
    assert [entry["value"] for entry in second["strings"]] == ["used3"]
    assert second["truncated"] is True
    last = refs(_call(_referenced_view()), only_referenced=True, limit=1, offset=2)
    assert [entry["value"] for entry in last["strings"]] == ["derived-used"]
    assert last["total"] == 3
    assert last["truncated"] is False


def test_string_refs_only_referenced_looks_up_each_string_once() -> None:
    view = _referenced_view()
    _, refs = get_tool("rex_string_refs")
    refs(_call(view), only_referenced=True)
    assert view.code_ref_requests == [(0x4000, 65), (0x4010, 65), (0x4020, 65), (0x4030, 65)]
    assert view.derived_code_ref_requests == [65, 65]


def test_string_refs_default_skips_lookups_for_unreturned_rows() -> None:
    view = _referenced_view()
    _, refs = get_tool("rex_string_refs")
    refs(_call(view), limit=1)
    assert view.code_ref_requests == [(0x4000, 65)]


def _read_fallback(memory: bytes, max_chars: int) -> dict[str, Any]:
    view = FakeBinaryView(memory={0x2000: memory})
    _, read = get_tool("rex_string_read_at")
    return read(_call(view), 0x2000, max_chars=max_chars)


@pytest.mark.parametrize("text", ["a", "ab", "abc"])
def test_string_read_at_fallback_reads_short_strings(text: str) -> None:
    result = _read_fallback(text.encode() + b"\x00", 8)
    assert result["value"] == text
    assert result["length"] == len(text)
    assert result["truncated"] is False
    assert result["detected"] is False


def test_string_read_at_fallback_accepts_newlines() -> None:
    result = _read_fallback(b"a\nb\x00", 8)
    assert result["value"] == "a\nb"
    assert result["length"] == 3


def test_string_read_at_fallback_rejects_a_leading_nul() -> None:
    with pytest.raises(FakeToolError) as exc:
        _read_fallback(b"\x00abc", 8)
    assert exc.value.code == "no_string"


def test_string_read_at_fallback_flags_a_run_one_past_the_bound() -> None:
    result = _read_fallback(b"abcde\x00", 4)
    assert result["value"] == "abcd"
    assert result["length"] == 4
    assert result["truncated"] is True


@pytest.mark.parametrize(
    "memory", [b"abcd\xff", b"abcd", b"abc\xff", b"abc", b"abcd\x80\x00"], ids=str
)
def test_string_read_at_fallback_rejects_unverifiable_runs(memory: bytes) -> None:
    with pytest.raises(FakeToolError) as exc:
        _read_fallback(memory, 4)
    assert exc.value.code == "no_string"


def test_string_read_at_fallback_with_one_char_needs_an_ascii_follower() -> None:
    result = _read_fallback(b"UH\xff", 1)
    assert result["value"] == "U"
    assert result["truncated"] is True
    with pytest.raises(FakeToolError) as exc:
        _read_fallback(b"U\xff", 1)
    assert exc.value.code == "no_string"
    assert _read_fallback(b"U\x00", 1)["truncated"] is False


class _CountingDerivedView(FakeBinaryView):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.derived_reads = 0

    @property
    @override
    def derived_strings(self) -> list[FakeDerivedString]:
        self.derived_reads += 1
        return []

    @derived_strings.setter
    @override
    def derived_strings(self, value: list[FakeDerivedString]) -> None:
        return None


def test_string_refs_reads_derived_strings_only_after_detected_ones() -> None:
    strings = [FakeStringReference(f"s{i}", 0x100 + i * 0x10) for i in range(3)]
    view = _CountingDerivedView(strings=strings)
    _, refs = get_tool("rex_string_refs")
    refs(_call(view), limit=2)
    assert view.derived_reads == 0
    refs(_call(view), limit=3)
    assert view.derived_reads == 1


def test_string_refs_only_referenced_counts_a_capped_string_as_referenced() -> None:
    filler = FakeFunction("filler", 0x9000, 0x9100)
    view = FakeBinaryView(
        strings=[FakeStringReference("big", 0x8000)],
        code_refs={0x8000: [FakeReferenceSource(filler, 0x9000 + index) for index in range(65)]},
    )
    _, refs = get_tool("rex_string_refs")
    entry = refs(_call(view), only_referenced=True)["strings"][0]
    assert len(entry["refs"]) == 64
    assert entry["refs_truncated"] is True


def test_string_read_at_a_mid_string_address_returns_the_whole_detected_string() -> None:
    view = FakeBinaryView(strings=[FakeStringReference("0123456789", 0x400034)])
    _, read = get_tool("rex_string_read_at")
    result = read(_call(view), 0x400037)
    assert result["address"] == "0x400034"
    assert result["length"] == 10
    assert result["value"] == "0123456789"
    assert result["detected"] is True
    assert read(_call(view), 0x40003D)["detected"] is True
    with pytest.raises(FakeToolError) as exc:
        read(_call(view), 0x40003E)
    assert exc.value.code == "no_string"


def test_string_read_at_fallback_pins_the_ascii_boundary_after_the_bound() -> None:
    assert _read_fallback(b"abcd\x7f", 4)["truncated"] is True
    with pytest.raises(FakeToolError) as exc:
        _read_fallback(b"abcd\x80", 4)
    assert exc.value.code == "no_string"
