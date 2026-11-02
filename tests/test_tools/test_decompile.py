from __future__ import annotations

from typing import override

import pytest
from helpers import (
    FakeBasicBlock,
    FakeBinaryView,
    FakeDisasmFunction,
    FakeDisassemblyLine,
    FakeFunction,
    FakeParsingToolCall,
    FakeToolError,
    RenderableText,
    _call,
    _disasm_view,
    _view_with_functions,
    get_tool,
)

from binja_plugin import tools
from binja_plugin.tools import decompile as decompile_tools


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
    assert scanned_result["scanned"] == decompile_tools._MAX_HLIL_GREP_FUNCTIONS
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
            {"max_lines": decompile_tools._MAX_DECOMPILE_LINES + 1},
            "Invalid integer parameter 'max_lines': "
            f"Must be at most {decompile_tools._MAX_DECOMPILE_LINES}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            decompile(FakeParsingToolCall(view), ["garbage"], **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message


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
    extract = decompile_tools._first_call_argument
    marker = decompile_tools._MAIN_LIBC_MARKER
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
            {"max_lines": decompile_tools._MAX_DECOMPILE_LINES + 1},
            "Invalid integer parameter 'max_lines': "
            f"Must be at most {decompile_tools._MAX_DECOMPILE_LINES}",
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
    quick(FakeParsingToolCall(resolvable), max_lines=decompile_tools._MAX_DECOMPILE_LINES)
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
