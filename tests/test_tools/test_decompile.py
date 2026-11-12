from __future__ import annotations

from typing import override

import pytest
from helpers import (
    NO_ALTERNATIVES,
    FakeDisasmFunction,
    FakeParsingToolCall,
    FakeToolError,
    _call,
    _disasm_view,
    _view_with_functions,
    get_tool,
    plain_gap_message,
)
from helpers_view import (
    FakeBasicBlock,
    FakeBinaryView,
    FakeDisassemblyLine,
    FakeFunction,
    RenderableText,
)

from binja_plugin import tools
from binja_plugin.tools import decompile as decompile_tools


def test_disasm_at_returns_function_and_window() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(view), 0x1104)
    assert result == {
        "function": {"start": "0x1100", "name": "main", **NO_ALTERNATIVES},
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
        assert exc.value.message == plain_gap_message("analyzed function", address)


def test_disasm_at_explains_a_miss_one_byte_past_a_function_end() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_at")
    # main ends at 0x1200; the byte there follows its terminator and belongs to no
    # function, so the error names main and the define action instead of a bare miss.
    with pytest.raises(FakeToolError) as exc:
        disasm(_call(view), 0x1200)
    assert exc.value.code == "invalid_params"
    assert exc.value.message.startswith("no analyzed function contains 0x1200; ")
    assert "immediately past the end of main at 0x1100" in exc.value.message
    assert "rex_function_define(start=0x1200)" in exc.value.message


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


def test_disasm_at_renders_a_full_cap_window_in_one_call() -> None:
    # Pin the inclusive 4096-instruction cap and reject the first value above it.
    lines: list[tuple[int | None, str]] = [
        (0x1000 + index, f"insn {index}") for index in range(4097)
    ]
    main = FakeDisasmFunction("main", 0x1000, 0x2001, blocks=[FakeBasicBlock(lines)])
    view = FakeBinaryView(functions=[main])
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(view), 0x1000, before=0, after=4096)
    assert [entry["address"] for entry in result["instructions"]] == [
        hex(0x1000 + index) for index in range(4097)
    ]
    assert result["truncated"] is False
    with pytest.raises(FakeToolError) as exc:
        disasm(_call(view), 0x1000, before=0, after=4097)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'after': Must be at most 4096"


def test_disasm_at_truncates_names_and_text() -> None:
    main = FakeDisasmFunction(
        "m" * 600, 0x1100, 0x1200, blocks=[FakeBasicBlock([(0x1100, "x" * 600)])]
    )
    view = FakeBinaryView(functions=[main])
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(view), 0x1100, before=0, after=0)
    assert result["function"]["name"].endswith("chars truncated]")
    assert result["instructions"][0]["text"].endswith("chars truncated]")


@pytest.mark.parametrize(
    ("regex", "function_filter", "parameter", "reason"),
    [
        ("[", "", "regex", "unterminated character set at position 0"),
        ("x", "(", "function_filter", "missing ), unterminated subpattern at position 0"),
        ("[", "(", "regex", "unterminated character set at position 0"),
    ],
)
def test_hlil_grep_names_the_parameter_with_the_invalid_regex(
    regex: str, function_filter: str, parameter: str, reason: str
) -> None:
    _, grep = get_tool("rex_hlil_grep")
    with pytest.raises(FakeToolError) as exc:
        grep(_call(FakeBinaryView()), regex, function_filter=function_filter)
    assert exc.value.code == "invalid_regex"
    assert exc.value.message == f"Invalid regular expression parameter '{parameter}': {reason}"


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
        "scan_incomplete": False,
        "skipped_no_hlil": 0,
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
    # A zero render budget proves nothing about matches: truncated stays untouched and
    # scan_incomplete says the view was never scanned.
    assert zero_scan == {
        "scanned": 0,
        "truncated": False,
        "scan_incomplete": True,
        "skipped_no_hlil": 0,
        "functions": [],
        "next_offset": 0,
    }
    with pytest.raises(FakeToolError) as exc:
        grep(_call(view), "(")
    assert exc.value.code == "invalid_regex"
    assert exc.value.message == (
        "Invalid regular expression parameter 'regex': missing ), unterminated subpattern"
        " at position 0"
    )
    # Out-of-range sizes are rejected with the mcp layer's argument-error convention.
    for kwargs, message in (
        ({"limit": -1}, "Invalid integer parameter 'limit': Must be at least 0"),
        (
            {"limit": tools._MAX_HLIL_GREP_LIMIT + 1},
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_HLIL_GREP_LIMIT}",
        ),
        ({"max_functions": -1}, "Invalid integer parameter 'max_functions': Must be at least 0"),
        (
            {"max_functions": decompile_tools._MAX_HLIL_GREP_FUNCTIONS + 1},
            "Invalid integer parameter 'max_functions': Must be at most "
            f"{decompile_tools._MAX_HLIL_GREP_FUNCTIONS}",
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
        max_functions=decompile_tools._MAX_HLIL_GREP_FUNCTIONS,
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
        for index in range(decompile_tools._MAX_HLIL_GREP_FUNCTIONS + 1)
    ]
    inert_view = FakeBinaryView(functions=inert)
    scanned_result = grep(
        _call(inert_view),
        "zzz",
        limit=tools._MAX_HLIL_GREP_LIMIT,
        max_functions=decompile_tools._MAX_HLIL_GREP_FUNCTIONS,
    )
    # The budget ran out before the view ended: the scan is incomplete, but no render
    # proved a match past the (empty) page, so truncated must stay false.
    assert scanned_result["scanned"] == decompile_tools._MAX_HLIL_GREP_FUNCTIONS
    assert scanned_result["truncated"] is False
    assert scanned_result["scan_incomplete"] is True


def test_hlil_grep_proves_truncation_past_non_matching_functions() -> None:
    functions = [
        FakeFunction("a0", 0x1000, 0x1010, hlil=RenderableText("call ax\n")),
        FakeFunction("b1", 0x1010, 0x1020, hlil=RenderableText("nop\n")),
        FakeFunction("a2", 0x1020, 0x1030, hlil=RenderableText("call ax\n")),
    ]
    view = FakeBinaryView(functions=functions)
    _, grep = get_tool("rex_hlil_grep")
    # The page holds a0; b1 renders inside the verification pass before a2 proves
    # truncation, so scanned counts it and next_offset lands on the proven match.
    assert grep(_call(view), "call", limit=1) == {
        "scanned": 3,
        "truncated": True,
        "scan_incomplete": False,
        "skipped_no_hlil": 0,
        "functions": [{"start": "0x1000", "name": "a0", "lines": ["call ax"]}],
        "next_offset": 2,
    }


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
        "scanned": 3,
        "truncated": True,
        "scan_incomplete": False,
        "skipped_no_hlil": 0,
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
        "scan_incomplete": False,
        "skipped_no_hlil": 0,
        "functions": [{"start": "0x1030", "name": "a3", "lines": ["call ax"]}],
        "next_offset": None,
    }
    beyond = grep(_call(view), "call", offset=10)
    assert beyond == {
        "scanned": 0,
        "truncated": False,
        "scan_incomplete": False,
        "skipped_no_hlil": 0,
        "functions": [],
        "next_offset": None,
    }
    with pytest.raises(FakeToolError) as exc:
        grep(_call(view), "call", offset=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"


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
                **NO_ALTERNATIVES,
                "index": 0,
                "lines": ["void main() {", "    return 0;", "}"],
                "truncated": False,
            },
            {
                "start": "0x2000",
                "name": "handler",
                **NO_ALTERNATIVES,
                "index": 1,
                "lines": ["void handler() {", "    recv(fd, buf, n);", "    return 1;", "}"],
                "truncated": False,
            },
        ],
        "errors": [],
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
                **NO_ALTERNATIVES,
                "index": 0,
                "lines": ["void handler() {", "    recv(fd, buf, n);"],
                "truncated": True,
            }
        ],
        "errors": [],
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
        "functions": [
            {
                "start": "0x3000",
                "name": "sink",
                **NO_ALTERNATIVES,
                "index": 0,
                "lines": [],
                "truncated": False,
            }
        ],
        "errors": [],
    }


def test_decompile_many_reports_a_bad_entry_per_item_and_renders_the_rest() -> None:
    view = _decompile_view()
    _, decompile = get_tool("rex_decompile_many")
    # An unanalyzed address, an unparsable expression, a non-string and a NUL entry each
    # become an errors row at their input index; the good entries still render.
    result = decompile(
        FakeParsingToolCall(view),
        ["0x1800", "0x1100", "garbage", 7, "0x1100\x00zzz", "0x2000"],
    )
    assert [(row["index"], row["name"]) for row in result["functions"]] == [
        (1, "main"),
        (5, "handler"),
    ]
    assert [(row["index"], row["address"]) for row in result["errors"]] == [
        (0, "0x1800"),
        (2, "garbage"),
        (3, "7"),
        (4, "0x1100\x00zzz"),
    ]
    assert result["errors"][0]["error"] == {
        "code": "invalid_params",
        "message": plain_gap_message("analyzed function", 0x1800),
    }
    assert result["errors"][1]["error"]["code"] == "invalid_params"
    assert "bad address expression" in result["errors"][1]["error"]["message"]
    assert result["errors"][2]["error"]["message"] == (
        "functions[3] must be a string address expression"
    )
    assert result["errors"][3]["error"]["message"] == "functions[4] must not contain NUL bytes"
    # Every entry bad: no functions, one error each, and the call still succeeds.
    all_bad = decompile(FakeParsingToolCall(view), ["0x1800", "0x1801"])
    assert all_bad["functions"] == []
    assert [row["index"] for row in all_bad["errors"]] == [0, 1]


def test_decompile_many_rejects_bad_batch_and_max_lines() -> None:
    view = _decompile_view()
    _, decompile = get_tool("rex_decompile_many")
    for batch in ([], ["0x1100"] * (decompile_tools._MAX_DECOMPILE_BATCH + 1)):
        with pytest.raises(FakeToolError) as exc:
            decompile(FakeParsingToolCall(view), batch)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == (
            "functions must contain between 1 and "
            f"{decompile_tools._MAX_DECOMPILE_BATCH} address expressions"
        )
    # Exactly the batch cap is accepted.
    at_cap = decompile(FakeParsingToolCall(view), ["0x1100"] * decompile_tools._MAX_DECOMPILE_BATCH)
    assert len(at_cap["functions"]) == decompile_tools._MAX_DECOMPILE_BATCH
    # The argument must be a list, not a bare value; bad entries are per-item errors.
    with pytest.raises(FakeToolError) as exc:
        decompile(FakeParsingToolCall(view), "0x1100")
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "functions must be a list of address expressions"
    # Range errors win over address resolution, and both bounds are inclusive.
    for kwargs, message in (
        ({"max_lines": 0}, "Invalid integer parameter 'max_lines': Must be at least 1"),
        (
            {"max_lines": decompile_tools._MAX_DECOMPILE_LINES + 1},
            "Invalid integer parameter 'max_lines': "
            f"Must be at most {decompile_tools._MAX_DECOMPILE_LINES}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            decompile(FakeParsingToolCall(view), ["garbage"], **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message


def test_disasm_many_renders_one_window_per_address() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_many")
    result = disasm(FakeParsingToolCall(view), ["0x1104", "0x2000"], max_lines=3)
    assert result == {
        "windows": [
            {
                "address": "0x1104",
                "index": 0,
                "function": {"start": "0x1100", "name": "main", **NO_ALTERNATIVES},
                "instructions": [
                    {"address": "0x1104", "text": "sub rsp, 0x20"},
                    {"address": "0x1108", "text": "mov eax, 1"},
                    {"address": "0x110d", "text": "leave"},
                ],
                "truncated": True,
            },
            {
                "address": "0x2000",
                "index": 1,
                "function": {"start": "0x2000", "name": "handler", **NO_ALTERNATIVES},
                "instructions": [
                    {"address": "0x2000", "text": "push rbp"},
                    {"address": "0x2001", "text": "ret"},
                ],
                "truncated": False,
            },
        ],
        "errors": [],
        "truncated": False,
        "next_offset": None,
    }


def test_disasm_many_anchors_inside_an_instruction() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_many")
    # 0x1105 falls inside "sub rsp, 0x20" (0x1104): the window starts at its start line.
    inside = disasm(FakeParsingToolCall(view), ["0x1105"], max_lines=1)
    assert inside["windows"][0]["instructions"] == [{"address": "0x1104", "text": "sub rsp, 0x20"}]


def test_disasm_many_clips_at_the_cross_window_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    # main renders 6 lines, handler 2: a budget of 7 takes main's window whole and
    # leaves handler for the continuation.
    monkeypatch.setattr(decompile_tools, "_MAX_DISASM_MANY_TOTAL_LINES", 7)
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_many")
    clipped = disasm(FakeParsingToolCall(view), ["0x1100", "0x2000"])
    assert [entry["address"] for entry in clipped["windows"]] == ["0x1100"]
    assert clipped["errors"] == []
    assert clipped["truncated"] is True
    assert clipped["next_offset"] == 1
    continuation = disasm(FakeParsingToolCall(view), ["0x2000"])
    assert [entry["address"] for entry in continuation["windows"]] == ["0x2000"]
    assert continuation["truncated"] is False

    # A budget smaller than the first window renders nothing and points the caller back
    # at the first address.
    monkeypatch.setattr(decompile_tools, "_MAX_DISASM_MANY_TOTAL_LINES", 3)
    nothing = disasm(FakeParsingToolCall(view), ["0x1100", "0x2000"])
    assert nothing["windows"] == []
    assert nothing["errors"] == []
    assert nothing["truncated"] is True
    assert nothing["next_offset"] == 0

    # A window landing exactly on the budget still fits: 6 + 2 == 8 echoes 8 lines.
    monkeypatch.setattr(decompile_tools, "_MAX_DISASM_MANY_TOTAL_LINES", 8)
    exact = disasm(FakeParsingToolCall(view), ["0x1100", "0x2000"])
    assert [entry["address"] for entry in exact["windows"]] == ["0x1100", "0x2000"]
    assert exact["errors"] == []
    assert exact["truncated"] is False
    assert exact["next_offset"] is None


def test_disasm_many_reports_errors_per_address() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_many")
    mixed = disasm(FakeParsingToolCall(view), ["0x1100", "not-an-address", "0x9999", 17])
    assert [window["index"] for window in mixed["windows"]] == [0]
    assert mixed["errors"] == [
        {
            "index": 1,
            "address": "not-an-address",
            "error": {
                "code": "invalid_params",
                "message": (
                    "bad address expression 'not-an-address': "
                    "unparsable address expression 'not-an-address'"
                ),
            },
        },
        {
            "index": 2,
            "address": "0x9999",
            "error": {
                "code": "invalid_params",
                "message": plain_gap_message("analyzed function", 0x9999),
            },
        },
        {
            "index": 3,
            "address": "17",
            "error": {
                "code": "invalid_params",
                "message": "addresses[3] must be a string address expression",
            },
        },
    ]
    assert mixed["truncated"] is False
    assert mixed["next_offset"] is None
    with pytest.raises(FakeToolError) as exc:
        disasm(FakeParsingToolCall(view), "0x1100")
    assert exc.value.message == "addresses must be a list of address expressions"
    with pytest.raises(FakeToolError) as exc:
        disasm(FakeParsingToolCall(view), [])
    assert exc.value.message == "addresses must contain between 1 and 64 address expressions"
    with pytest.raises(FakeToolError) as exc:
        disasm(FakeParsingToolCall(view), [f"0x{address:x}" for address in range(65)])
    assert exc.value.message == "addresses must contain between 1 and 64 address expressions"
    with pytest.raises(FakeToolError) as exc:
        disasm(FakeParsingToolCall(view), ["0x1100"], max_lines=513)
    assert exc.value.message == "Invalid integer parameter 'max_lines': Must be at most 512"


def test_disasm_many_reports_pending_analysis() -> None:
    # A defined-but-unanalyzed function is invisible to containment; the tools answer
    # analysis_pending with the recovery path instead of a bare "no function".
    pending = FakeFunction("sub_4000", 0x4000, 0x4010)
    view = FakeBinaryView(pending_functions=[pending])
    _, disasm = get_tool("rex_disasm_many")
    pending_result = disasm(FakeParsingToolCall(view), ["0x4000"])
    assert pending_result["errors"] == [
        {
            "index": 0,
            "address": "0x4000",
            "error": {
                "code": "analysis_pending",
                "message": (
                    "function at 0x4000 exists but has not been analyzed yet; wait for analysis "
                    "(rex_analysis_wait, or rex_function_define with wait=true) "
                    "or run bn_analysis_update"
                ),
            },
        }
    ]
    # Same diagnostic through the single-window tool and the batch decompiler.
    _, at = get_tool("rex_disasm_at")
    with pytest.raises(FakeToolError) as exc:
        at(_call(view), 0x4000)
    assert exc.value.code == "analysis_pending"
    _, decompile = get_tool("rex_decompile_many")
    decompile_result = decompile(FakeParsingToolCall(view), ["0x4000"])
    assert decompile_result["functions"] == []
    assert decompile_result["errors"] == pending_result["errors"]
    # An address with no function at all keeps the caller's own miss code.
    with pytest.raises(FakeToolError) as exc:
        at(_call(view), 0x9999)
    assert exc.value.code == "invalid_params"
