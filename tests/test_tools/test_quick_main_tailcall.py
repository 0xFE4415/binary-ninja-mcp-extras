from __future__ import annotations

from typing import Any, override

import pytest
from helpers import (
    FakeHighLevelILConstPtr,
    FakeHighLevelILTailcall,
    FakeParsingToolCall,
    get_tool,
)
from helpers_view import (
    FakeAnalysisSkipReason,
    FakeBinaryView,
    FakeFunction,
    RenderableText,
)

_STUB_TEXT = "return main_2000(argc, argv, envp) __tailcall"


class _FakeHlil:
    def __init__(self, blocks: list[list[object]], text: str = _STUB_TEXT) -> None:
        self.basic_blocks = blocks
        self._text = text

    @override
    def __str__(self) -> str:
        return self._text


class _FakeOtherInstruction:
    def __init__(self) -> None:
        self.dest = FakeHighLevelILConstPtr(0x2000)


class _FakeNonConstantDestination:
    constant = 0x2000


def _tailcall_to(address: int) -> object:
    return FakeHighLevelILTailcall(FakeHighLevelILConstPtr(address))


def _stub(name: str, start: int, target: int) -> FakeFunction:
    return FakeFunction(name, start, start + 0x10, hlil=_FakeHlil([[_tailcall_to(target)]]))


def _body(name: str, start: int) -> FakeFunction:
    return FakeFunction(name, start, start + 0x100, hlil=RenderableText("return 0"))


def _entry() -> FakeFunction:
    return FakeFunction("_start", 0x1000, 0x1100, hlil=RenderableText("void _start() {}"))


def _quick(*functions: FakeFunction) -> dict[str, Any]:
    view = FakeBinaryView(entry_point=0x1000, functions=[_entry(), *functions])
    _, quick = get_tool("rex_quick_main")
    return quick(FakeParsingToolCall(view))


def _note(real_name: str, real_address: int) -> str:
    return f"main is a tail-call stub; its real body is {real_name} at {real_address:#x}"


def test_a_tail_call_stub_main_names_the_real_body_and_stays_main() -> None:
    result = _quick(_stub("main", 0x3000, 0x2000), _body("main_2000", 0x2000))
    assert result["method"] == "symbol"
    assert result["main"] == "0x3000"
    assert result["function"]["name"] == "main"
    assert result["lines"] == [_STUB_TEXT]
    assert result["note"] == _note("main_2000", 0x2000)


def test_a_tail_call_stub_found_through_the_entry_pointer_gets_the_note() -> None:
    entry = FakeFunction(
        "_start",
        0x1000,
        0x1100,
        hlil=RenderableText("void _start() {\n    __libc_start_main(0x3000, argc);\n}"),
    )
    view = FakeBinaryView(
        entry_point=0x1000,
        functions=[entry, _stub("sub_3000", 0x3000, 0x2000), _body("real", 0x2000)],
    )
    _, quick = get_tool("rex_quick_main")
    result = quick(FakeParsingToolCall(view))
    assert result["method"] == "entry-arg"
    assert result["main"] == "0x3000"
    assert result["note"] == _note("real", 0x2000)


def test_a_chain_of_stubs_names_the_final_body() -> None:
    result = _quick(
        _stub("main", 0x3000, 0x3100),
        _stub("hop_one", 0x3100, 0x3200),
        _stub("hop_two", 0x3200, 0x2000),
        _body("real", 0x2000),
    )
    assert result["note"] == _note("real", 0x2000)


def _chain(hops: int) -> list[FakeFunction]:
    functions = [_stub("main", 0x10000, 0x10100)]
    for hop in range(1, hops):
        functions.append(_stub(f"hop_{hop}", 0x10000 + 0x100 * hop, 0x10000 + 0x100 * (hop + 1)))
    functions.append(_body("real", 0x10000 + 0x100 * hops))
    return functions


def test_a_chain_of_eight_hops_still_names_the_final_body() -> None:
    assert _quick(*_chain(8))["note"] == _note("real", 0x10800)


def test_a_chain_of_nine_hops_gives_no_note() -> None:
    assert _quick(*_chain(9))["note"] is None


def test_a_stub_cycle_has_no_real_body_and_gives_no_note() -> None:
    result = _quick(_stub("main", 0x3000, 0x3100), _stub("other", 0x3100, 0x3000))
    assert result["note"] is None


def test_a_stub_that_jumps_to_itself_gives_no_note() -> None:
    assert _quick(_stub("main", 0x3000, 0x3000))["note"] is None


def test_a_stub_whose_target_is_not_a_function_start_gives_no_note() -> None:
    assert _quick(_stub("main", 0x3000, 0x2040), _body("real", 0x2000))["note"] is None


def test_a_stub_whose_target_is_not_in_any_function_gives_no_note() -> None:
    assert _quick(_stub("main", 0x3000, 0x9000))["note"] is None


def test_a_stub_to_a_target_without_hlil_still_names_it() -> None:
    result = _quick(_stub("main", 0x3000, 0x2000), FakeFunction("imp", 0x2000, 0x2010))
    assert result["note"] == _note("imp", 0x2000)


def test_a_stub_target_name_is_truncated() -> None:
    result = _quick(_stub("main", 0x3000, 0x2000), _body("n" * 600, 0x2000))
    assert result["note"] == _note(f"{'n' * 512}... [88 chars truncated]", 0x2000)


def test_a_tail_call_through_a_non_constant_destination_gives_no_note() -> None:
    non_constant = FakeFunction(
        "main",
        0x3000,
        0x3010,
        hlil=_FakeHlil([[FakeHighLevelILTailcall(_FakeNonConstantDestination())]]),
    )
    assert _quick(non_constant, _body("real", 0x2000))["note"] is None


def test_a_single_statement_that_is_not_a_tail_call_gives_no_note() -> None:
    other = FakeFunction("main", 0x3000, 0x3010, hlil=_FakeHlil([[_FakeOtherInstruction()]]))
    assert _quick(other, _body("real", 0x2000))["note"] is None


@pytest.mark.parametrize(
    "blocks",
    [
        [[_tailcall_to(0x2000), _tailcall_to(0x2000)]],
        [[_tailcall_to(0x2000)], [_tailcall_to(0x2000)]],
        [[_FakeOtherInstruction(), _tailcall_to(0x2000)]],
    ],
    ids=["two-in-one-block", "one-in-each-of-two-blocks", "statement-before-the-tail-call"],
)
def test_main_with_more_than_the_one_tail_call_is_not_a_stub(blocks: list[list[object]]) -> None:
    main = FakeFunction("main", 0x3000, 0x3010, hlil=_FakeHlil(blocks))
    assert _quick(main, _body("real", 0x2000))["note"] is None


def test_a_function_with_no_statements_is_not_a_stub() -> None:
    main = FakeFunction("main", 0x3000, 0x3010, hlil=_FakeHlil([[]]))
    assert _quick(main, _body("real", 0x2000))["note"] is None


def test_the_rendered_tail_call_text_alone_does_not_make_a_stub() -> None:
    main = FakeFunction("main", 0x3000, 0x3010, hlil=RenderableText(_STUB_TEXT))
    assert _quick(main, _body("main_2000", 0x2000))["note"] is None


def test_a_main_with_real_code_has_no_note() -> None:
    assert _quick(_body("main", 0x3000))["note"] is None


def test_the_stub_note_names_the_function_starting_at_the_target_not_a_parent_containing_it() -> (
    None
):
    cold = FakeFunction("cold", 0x2000, 0x2040, hlil=RenderableText("return"))
    parent = FakeFunction("parent", 0x1F00, 0x2100, hlil=RenderableText("return"))
    assert _quick(_stub("main", 0x3000, 0x2000), cold, parent)["note"] == _note("cold", 0x2000)


def test_a_skipped_target_is_still_named_as_the_real_body() -> None:
    skipped = FakeFunction(
        "real",
        0x2000,
        0x2100,
        analysis_skipped=True,
        analysis_skip_reason=FakeAnalysisSkipReason.AlwaysSkipReason,
    )
    assert _quick(_stub("main", 0x3000, 0x2000), skipped)["note"] == _note("real", 0x2000)
