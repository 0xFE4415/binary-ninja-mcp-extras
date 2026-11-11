from __future__ import annotations

from typing import Any, override

import pytest
from helpers import (
    FakeHighLevelILConst,
    FakeHighLevelILConstPtr,
    FakeHighLevelILImport,
    FakeHighLevelILTailcall,
    FakeHighLevelILVar,
    FakeParsingToolCall,
    get_tool,
)
from helpers_view import (
    FakeAnalysisSkipReason,
    FakeArchitecture,
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


class _FakeCallArgument:
    pass


def _forwarded_arguments() -> tuple[object, ...]:
    return (FakeHighLevelILVar(), FakeHighLevelILVar(), FakeHighLevelILVar())


def _tailcall_to(address: int, params: tuple[object, ...] | None = None) -> object:
    arguments = _forwarded_arguments() if params is None else params
    return FakeHighLevelILTailcall(FakeHighLevelILConstPtr(address), arguments)


def _stub(name: str, start: int, target: int) -> FakeFunction:
    return FakeFunction(name, start, start + 0x10, hlil=_FakeHlil([[_tailcall_to(target)]]))


def _body(name: str, start: int) -> FakeFunction:
    return FakeFunction(name, start, start + 0x100, hlil=RenderableText("return 0"))


def _entry() -> FakeFunction:
    return FakeFunction("_start", 0x1000, 0x1100, hlil=RenderableText("void _start() {}"))


def _quick(*functions: FakeFunction, pending: list[FakeFunction] | None = None) -> dict[str, Any]:
    view = FakeBinaryView(
        entry_point=0x1000, functions=[_entry(), *functions], pending_functions=pending
    )
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


def _plt_thunk(name: str, start: int, symbol_type: str = "ImportedFunctionSymbol") -> FakeFunction:
    return FakeFunction(
        name,
        start,
        start + 0x10,
        hlil=_FakeHlil(
            [[FakeHighLevelILTailcall(FakeHighLevelILImport(0x424F20), (_FakeCallArgument(),))]]
        ),
        symbol_type=symbol_type,
    )


def test_a_stub_to_a_library_import_thunk_gives_no_note() -> None:
    assert _quick(_stub("main", 0x3000, 0x2000), _plt_thunk("system", 0x2000))["note"] is None


def test_a_chain_of_stubs_ending_in_an_import_thunk_gives_no_note() -> None:
    result = _quick(
        _stub("main", 0x3000, 0x3100),
        _stub("hop", 0x3100, 0x2000),
        _plt_thunk("system", 0x2000),
    )
    assert result["note"] is None


def test_a_body_with_a_library_function_symbol_is_still_a_real_body() -> None:
    library = FakeFunction(
        "memcpy", 0x2000, 0x2100, hlil=RenderableText("return"), symbol_type="LibraryFunctionSymbol"
    )
    assert _quick(_stub("main", 0x3000, 0x2000), library)["note"] == _note("memcpy", 0x2000)


def test_a_stub_to_a_defined_but_unanalyzed_function_still_names_it() -> None:
    pending = FakeFunction("real", 0x2000, 0x2100)
    result = _quick(_stub("main", 0x3000, 0x2000), pending=[pending])
    assert result["note"] == _note("real", 0x2000)


def test_the_stub_note_picks_the_architecture_name_when_two_functions_share_the_target() -> None:
    thumb = FakeFunction("zeta", 0x2000, 0x2100, arch=FakeArchitecture("thumb2"))
    arm = FakeFunction("alpha", 0x2000, 0x2100, arch=FakeArchitecture("armv7"))
    assert _quick(_stub("main", 0x3000, 0x2000), thumb, arm)["note"] == _note("alpha", 0x2000)


def test_an_entry_function_named_main_that_is_a_stub_gets_the_note() -> None:
    entry_stub = _stub("main", 0x1000, 0x2000)
    view = FakeBinaryView(entry_point=0x1000, functions=[entry_stub, _body("real", 0x2000)])
    _, quick = get_tool("rex_quick_main")
    result = quick(FakeParsingToolCall(view))
    assert result["method"] == "symbol"
    assert result["main"] == "0x1000"
    assert result["note"] == _note("real", 0x2000)


def test_a_renamed_import_thunk_is_recognised_by_its_import_tail_call() -> None:
    renamed = _plt_thunk("my_system", 0x2000, "FunctionSymbol")
    assert _quick(_stub("main", 0x3000, 0x2000), renamed)["note"] is None


def test_a_renamed_import_thunk_after_a_hop_gives_no_note() -> None:
    renamed = _plt_thunk("my_system", 0x2000, "FunctionSymbol")
    result = _quick(_stub("main", 0x3000, 0x3100), _stub("hop", 0x3100, 0x2000), renamed)
    assert result["note"] is None


def _main_with_tailcall(params: tuple[object, ...]) -> FakeFunction:
    return FakeFunction("main", 0x3000, 0x3010, hlil=_FakeHlil([[_tailcall_to(0x2000, params)]]))


@pytest.mark.parametrize(
    "params",
    [
        (),
        (FakeHighLevelILVar(),),
        (FakeHighLevelILConst(1),),
        (FakeHighLevelILConstPtr(0x5000),),
        (FakeHighLevelILVar(), FakeHighLevelILConst(1), FakeHighLevelILConstPtr(0x5000)),
    ],
    ids=["none", "variable", "constant", "constant-pointer", "mixed"],
)
def test_a_tail_call_that_only_forwards_variables_and_constants_is_a_stub(
    params: tuple[object, ...],
) -> None:
    result = _quick(_main_with_tailcall(params), _body("real", 0x2000))
    assert result["note"] == _note("real", 0x2000)


@pytest.mark.parametrize(
    "params",
    [
        (_FakeCallArgument(),),
        (FakeHighLevelILVar(), _FakeCallArgument()),
        (_FakeCallArgument(), FakeHighLevelILVar()),
    ],
    ids=["only-computed", "computed-last", "computed-first"],
)
def test_a_tail_call_with_a_computed_argument_does_work_and_is_not_a_stub(
    params: tuple[object, ...],
) -> None:
    result = _quick(_main_with_tailcall(params), _body("real", 0x2000))
    assert result["note"] is None


def test_a_hop_that_computes_its_arguments_is_named_as_the_body() -> None:
    hop = FakeFunction(
        "hop",
        0x3100,
        0x3110,
        hlil=_FakeHlil([[_tailcall_to(0x2000, (_FakeCallArgument(),))]]),
    )
    result = _quick(_stub("main", 0x3000, 0x3100), hop, _body("real", 0x2000))
    assert result["note"] == _note("hop", 0x3100)


class _CountingFunction(FakeFunction):
    hlil_reads = 0

    @property
    @override
    def hlil(self) -> object:
        type(self).hlil_reads += 1
        return self._counted_hlil

    @hlil.setter
    @override
    def hlil(self, value: object) -> None:
        self._counted_hlil = value


def _counted(name: str, start: int, hlil: object) -> _CountingFunction:
    function = _CountingFunction(name, start, start + 0x10)
    function.hlil = hlil
    return function


def test_each_hlil_is_fetched_once_for_a_stub_chain() -> None:
    _CountingFunction.hlil_reads = 0
    main = _counted("main", 0x3000, _FakeHlil([[_tailcall_to(0x3100)]]))
    hop = _counted("hop", 0x3100, _FakeHlil([[_tailcall_to(0x2000)]]))
    real = _counted("real", 0x2000, RenderableText("return 0"))
    result = _quick(main, hop, real)
    assert result["note"] == _note("real", 0x2000)
    assert _CountingFunction.hlil_reads == 3


def test_main_hlil_is_fetched_once_when_it_is_not_a_stub() -> None:
    _CountingFunction.hlil_reads = 0
    result = _quick(_counted("main", 0x3000, RenderableText("return 0")))
    assert result["note"] is None
    assert _CountingFunction.hlil_reads == 1


def test_main_hlil_is_fetched_once_when_it_is_missing() -> None:
    _CountingFunction.hlil_reads = 0
    result = _quick(_counted("main", 0x3000, None))
    assert result["lines"] == []
    assert _CountingFunction.hlil_reads == 1
