from __future__ import annotations

import pytest
from helpers import (
    FakeBinaryView,
    FakeDerivedString,
    FakeDerivedStringLocation,
    FakeFunction,
    FakeReferenceSource,
    FakeStringReference,
    FakeToolError,
    _call,
    get_tool,
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
        read(_call(view), 0x2000)
    assert exc.value.code == "no_string"


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
        read(_call(view), 0x1100, max_chars=strings._MAX_STRING_READ_CHARS + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'max_chars': Must be at most {strings._MAX_STRING_READ_CHARS}"
    )
    # Both bounds are inclusive: exactly 1 and exactly the cap are accepted.
    at_minimum = read(_call(view), 0x1100, max_chars=1)
    assert at_minimum["value"] == "h... [4 chars truncated]"
    assert at_minimum["truncated"] is True


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
