from __future__ import annotations

import itertools
from collections.abc import Callable
from pathlib import Path
from typing import Any, override

import pytest
from helpers import FakeParsingToolCall, FakeToolError, _call, _use_export_root, get_tool
from helpers_dataflow import FakeHLIL, FakeInstruction, FakeMLILInstructions, const, set_var
from helpers_uidf import FakeVariable
from helpers_view import (
    FakeArchitecture,
    FakeBasicBlock,
    FakeBinaryView,
    FakeComponent,
    FakeFunction,
    RenderableText,
)

from binja_plugin import tools

ADDRESS = 0x40AD9A


class _LayerHlil(FakeHLIL):
    @override
    def __str__(self) -> str:
        return "return 0"


class _Layer(FakeFunction):
    def __init__(
        self,
        name: str,
        start: int,
        end: int,
        *,
        arch: FakeArchitecture | None = None,
        extra_ranges: tuple[tuple[int, int], ...] = (),
    ) -> None:
        variable = FakeVariable("rax_1")
        definition = set_var(ADDRESS, variable, const(1))
        statement = FakeInstruction("HLIL_RET", ADDRESS)
        super().__init__(
            name,
            start,
            end,
            hlil=_LayerHlil([[statement]]),
            mlil=FakeMLILInstructions(
                [definition], definitions={variable: [definition]}, uses={variable: []}
            ),
            vars=[variable],
            arch=arch,
            extra_ranges=extra_ranges,
        )
        self.basic_blocks = [FakeBasicBlock([(ADDRESS, "nop")])]


def _cold() -> _Layer:
    return _Layer("sort_files.cold", 0x40AD60, 0x40AD9F)


def _flush() -> _Layer:
    return _Layer("flush_stdout", 0x40AD7F, 0x40AD9F)


def _discontiguous() -> _Layer:
    return _Layer("sub_412c10", 0x412C10, 0x412F21, extra_ranges=((0x40AD80, 0x40AD9F),))


COLD_ENTRY = {"start": "0x40ad60", "name": "sort_files.cold"}
FLUSH_ENTRY = {"start": "0x40ad7f", "name": "flush_stdout"}
DISCONTIGUOUS_ENTRY = {"start": "0x412c10", "name": "sub_412c10"}
CHOSEN = {
    **COLD_ENTRY,
    "also_containing": [FLUSH_ENTRY, DISCONTIGUOUS_ENTRY],
    "same_name": [],
}


def _descending_view(**options: Any) -> FakeBinaryView:
    return FakeBinaryView(
        functions=[_discontiguous(), _flush(), _cold()], entry_point=ADDRESS, **options
    )


def _tool(name: str) -> Any:
    return get_tool(name)[1]


def _row_entry(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row[key] for key in CHOSEN}


def _constraints(view: FakeBinaryView) -> Any:
    return _tool("rex_function_constraints")(_call(view), function=ADDRESS)["function"]


def _statements(view: FakeBinaryView) -> Any:
    return _tool("rex_hlil_statements")(_call(view), function=ADDRESS)["function"]


def _uses(view: FakeBinaryView) -> Any:
    return _tool("rex_mlil_uses")(_call(view), function=ADDRESS, address=ADDRESS)["function"]


def _parameter(view: FakeBinaryView) -> Any:
    return _tool("rex_parameter_variables")(_call(view), function=ADDRESS, parameter="rax_1")[
        "function"
    ]


def _disasm_at(view: FakeBinaryView) -> Any:
    return _tool("rex_disasm_at")(_call(view), ADDRESS)["function"]


def _disasm_many(view: FakeBinaryView) -> Any:
    return _tool("rex_disasm_many")(FakeParsingToolCall(view), ["0x40ad9a"])["windows"][0][
        "function"
    ]


def _decompile_many(view: FakeBinaryView) -> Any:
    rows = _tool("rex_decompile_many")(FakeParsingToolCall(view), ["0x40ad9a"])["functions"]
    return _row_entry(rows[0])


def _export_disasm(view: FakeBinaryView) -> Any:
    return _tool("rex_export_disasm")(_call(view), ADDRESS, filename="layers.txt")["function"]


def _call_paths_from(view: FakeBinaryView) -> Any:
    return _tool("rex_call_paths")(_call(view), ADDRESS, ADDRESS)["from_function"]


def _call_paths_to(view: FakeBinaryView) -> Any:
    return _tool("rex_call_paths")(_call(view), ADDRESS, ADDRESS)["to_function"]


def _undefine(view: FakeBinaryView) -> Any:
    return _tool("rex_function_undefine")(_call(view), ADDRESS)


def _component_add(view: FakeBinaryView) -> Any:
    rows = _tool("rex_component_add_functions")(FakeParsingToolCall(view), "/", ["0x40ad9a"])[
        "results"
    ]
    return _row_entry(rows[0])


def _annotate(view: FakeBinaryView) -> Any:
    rows = _tool("rex_annotate_many")(FakeParsingToolCall(view), [{"addr": ADDRESS}])["results"]
    return rows[0]["function"]


def _uidf_set(view: FakeBinaryView) -> Any:
    return _tool("rex_uidf_set")(_call(view), ADDRESS, "rax_1", "0x10")["function"]


def _uidf_set_many(view: FakeBinaryView) -> Any:
    items = [{"variable": "rax_1", "value": "0x10"}]
    return _tool("rex_uidf_set_many")(FakeParsingToolCall(view), ADDRESS, items)["function"]


def _uidf_clear_all(view: FakeBinaryView) -> Any:
    return _tool("rex_uidf_clear")(_call(view), ADDRESS)["function"]


def _uidf_clear_variable(view: FakeBinaryView) -> Any:
    return _tool("rex_uidf_clear")(_call(view), ADDRESS, "rax_1")["function"]


def _uidf_list(view: FakeBinaryView) -> Any:
    return _tool("rex_uidf_list")(_call(view), ADDRESS)["function"]


def _quick_main(view: FakeBinaryView) -> Any:
    return _tool("rex_quick_main")(FakeParsingToolCall(view))["function"]


_RESOLVING_TOOLS: list[Callable[[FakeBinaryView], Any]] = [
    _constraints,
    _statements,
    _uses,
    _parameter,
    _disasm_at,
    _disasm_many,
    _decompile_many,
    _export_disasm,
    _call_paths_from,
    _call_paths_to,
    _undefine,
    _component_add,
    _annotate,
    _uidf_set,
    _uidf_set_many,
    _uidf_clear_all,
    _uidf_clear_variable,
    _uidf_list,
    _quick_main,
]


@pytest.mark.parametrize("resolve", _RESOLVING_TOOLS, ids=lambda resolve: resolve.__name__)
def test_every_tool_reports_the_chosen_function_and_every_loser(
    resolve: Callable[[FakeBinaryView], Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _descending_view(component_root=FakeComponent("__root__", "guid-root"))
    assert resolve(view) == CHOSEN


@pytest.mark.parametrize(
    "order", list(itertools.permutations(range(3))), ids=lambda order: "".join(map(str, order))
)
def test_the_pick_does_not_depend_on_the_order_the_core_lists(order: tuple[int, ...]) -> None:
    layers = [_cold(), _flush(), _discontiguous()]
    view = FakeBinaryView(functions=[layers[index] for index in order])
    assert _disasm_at(view) == CHOSEN


def test_the_pick_is_the_lowest_start_even_when_the_address_is_nearer_another_start() -> None:
    view = _descending_view()
    assert view.get_functions_containing(ADDRESS)[0].name == "sub_412c10"
    assert _disasm_at(view)["name"] == "sort_files.cold"


def test_a_single_containing_function_has_no_alternatives() -> None:
    view = FakeBinaryView(functions=[_cold(), _discontiguous()])
    entry = _tool("rex_disasm_at")(_call(view), 0x40AD62)["function"]
    assert entry == {**COLD_ENTRY, "also_containing": [], "same_name": []}


def test_the_architecture_name_breaks_a_tie_between_equal_starts() -> None:
    thumb = _Layer("twin", 0x1000, 0x2000, arch=FakeArchitecture("thumb2"))
    arm = _Layer("twin_arm", 0x1000, 0x2000, arch=FakeArchitecture("armv7"))
    expected = {
        "start": "0x1000",
        "name": "twin_arm",
        "also_containing": [{"start": "0x1000", "name": "twin"}],
        "same_name": [],
    }
    orders: list[list[FakeFunction]] = [[thumb, arm], [arm, thumb]]
    for functions in orders:
        view = FakeBinaryView(functions=functions)
        assert _tool("rex_disasm_at")(_call(view), 0x1000)["function"] == expected


def test_functions_sharing_the_chosen_name_are_listed_by_start() -> None:
    late = _Layer("_start", 0x40D5D0, 0x40D5F0)
    early = _Layer("_start", 0x40D5B0, 0x40D5D0)
    unrelated = _Layer("deregister_tm_clones", 0x40D600, 0x40D620)
    view = FakeBinaryView(functions=[unrelated, late, early])
    entry = _tool("rex_disasm_at")(_call(view), 0x40D5D4)["function"]
    assert entry == {
        "start": "0x40d5d0",
        "name": "_start",
        "also_containing": [],
        "same_name": [{"start": "0x40d5b0", "name": "_start"}],
    }
    assert _tool("rex_disasm_at")(_call(view), 0x40D604)["function"]["same_name"] == []


def test_a_same_name_function_that_also_contains_the_address_is_listed_in_both() -> None:
    first = _Layer("dup", 0x1000, 0x2000)
    second = _Layer("dup", 0x1800, 0x2000)
    view = FakeBinaryView(functions=[second, first])
    entry = _tool("rex_disasm_at")(_call(view), 0x1900)["function"]
    other = {"start": "0x1800", "name": "dup"}
    assert entry == {
        "start": "0x1000",
        "name": "dup",
        "also_containing": [other],
        "same_name": [other],
    }


def test_alternative_names_are_truncated_like_every_echoed_name() -> None:
    long_name = "n" * (tools._MAX_CHARS + 5)
    view = FakeBinaryView(
        functions=[_Layer("a", 0x1000, 0x2000), _Layer(long_name, 0x1100, 0x2000)]
    )
    entry = _tool("rex_disasm_at")(_call(view), 0x1200)["function"]
    assert entry["also_containing"] == [
        {"start": "0x1100", "name": "n" * tools._MAX_CHARS + "... [5 chars truncated]"}
    ]


@pytest.mark.parametrize(
    ("losers", "listed"), [(0, 0), (1, 1), (63, 63), (64, 64), (65, 64), (70, 64)]
)
def test_each_alternative_list_stops_at_sixty_four_keeping_the_lowest_starts(
    losers: int, listed: int
) -> None:
    layers = [_Layer(f"layer{index}", 0x1000 + index, 0x9000) for index in range(losers + 1)]
    view = FakeBinaryView(functions=list(reversed(layers)))
    entry = _tool("rex_disasm_at")(_call(view), 0x8000)["function"]
    assert entry["name"] == "layer0"
    assert [item["start"] for item in entry["also_containing"]] == [
        hex(0x1000 + index) for index in range(1, listed + 1)
    ]


@pytest.mark.parametrize(("twins", "listed"), [(64, 63), (65, 64), (66, 64)])
def test_the_same_name_list_stops_at_sixty_four_keeping_the_lowest_starts(
    twins: int, listed: int
) -> None:
    layers = [
        _Layer("twin", 0x1000 * (index + 1), 0x1000 * (index + 1) + 0x100) for index in range(twins)
    ]
    view = FakeBinaryView(functions=list(reversed(layers)))
    entry = _tool("rex_disasm_at")(_call(view), 0x1000)["function"]
    assert entry["start"] == "0x1000"
    assert [item["start"] for item in entry["same_name"]] == [
        hex(0x1000 * (index + 2)) for index in range(listed)
    ]


def test_function_containing_lists_in_the_order_the_other_tools_pick() -> None:
    view = _descending_view()
    result = _tool("rex_function_containing")(_call(view), ADDRESS)
    assert result == {
        "functions": [COLD_ENTRY, FLUSH_ENTRY, DISCONTIGUOUS_ENTRY],
        "truncated": False,
    }


def test_function_containing_truncates_after_ordering_by_start() -> None:
    cap = 64
    layers = [_Layer(f"layer{index}", 0x1000 + index, 0x9000) for index in range(cap + 3)]
    view = FakeBinaryView(functions=list(reversed(layers)))
    result = _tool("rex_function_containing")(_call(view), 0x8000)
    assert [entry["name"] for entry in result["functions"]] == [f"layer{i}" for i in range(cap)]
    assert result["truncated"] is True


def test_undefine_removes_the_function_it_reports() -> None:
    view = _descending_view()
    entry = _undefine(view)
    assert [function.name for function in view.removed_functions] == [entry["name"]]
    assert entry["name"] == "sort_files.cold"


def test_annotate_changes_the_function_its_row_reports_naming_it_as_resolved() -> None:
    view = _descending_view()
    rows = _tool("rex_annotate_many")(
        FakeParsingToolCall(view), [{"addr": ADDRESS, "name": "renamed"}]
    )["results"]
    assert rows == [{"addr": "0x40ad60", "ok": True, "function": CHOSEN}]
    assert [function.name for function in view.functions] == [
        "sub_412c10",
        "flush_stdout",
        "renamed",
    ]


def test_component_add_puts_the_reported_function_in_the_component() -> None:
    root = FakeComponent("__root__", "guid-root")
    view = _descending_view(component_root=root)
    rows = _tool("rex_component_add_functions")(FakeParsingToolCall(view), "/", ["0x40ad9a"])
    assert [function.name for function in root.added_functions] == ["sort_files.cold"]
    assert _row_entry(rows["results"][0]) == CHOSEN


def test_uidf_set_informs_the_reported_function() -> None:
    view = _descending_view()
    result = _tool("rex_uidf_set")(_call(view), ADDRESS, "rax_1", "0x10")
    cold, flush, discontiguous = view.functions[2], view.functions[1], view.functions[0]
    assert result["function"] == CHOSEN
    assert len(cold.set_user_var_value_calls) == 1
    assert flush.set_user_var_value_calls == []
    assert discontiguous.set_user_var_value_calls == []


def test_batch_rows_each_carry_their_own_resolution() -> None:
    view = _descending_view()
    rows = _tool("rex_decompile_many")(FakeParsingToolCall(view), ["0x40ad9a", "0x412c12"])
    assert [_row_entry(row) for row in rows["functions"]] == [
        CHOSEN,
        {**DISCONTIGUOUS_ENTRY, "also_containing": [], "same_name": []},
    ]


def test_call_paths_report_each_endpoint_separately() -> None:
    view = _descending_view()
    result = _tool("rex_call_paths")(_call(view), ADDRESS, 0x412C12)
    assert result["from_function"] == CHOSEN
    assert result["to_function"] == {
        **DISCONTIGUOUS_ENTRY,
        "also_containing": [],
        "same_name": [],
    }
    assert result["reachable"] is False


def test_a_containment_miss_still_rejects_without_choosing() -> None:
    with pytest.raises(FakeToolError) as error:
        _tool("rex_disasm_at")(_call(_descending_view()), 0x500000)
    assert error.value.code == "invalid_params"
    assert error.value.message.startswith("no analyzed function contains 0x500000")


def test_quick_main_resolves_the_entry_argument_through_the_same_rule() -> None:
    entry = FakeFunction(
        "_start",
        0x1000,
        0x1100,
        hlil=RenderableText("void _start() {\n    __libc_start_main(0x401234, argc, argv);\n}"),
    )
    outer = FakeFunction("main_outer", 0x401200, 0x401400, hlil=RenderableText("return 0"))
    inner = FakeFunction("main_inner", 0x401234, 0x401400, hlil=RenderableText("return 1"))
    view = FakeBinaryView(entry_point=0x1000, functions=[inner, entry, outer])
    result = _tool("rex_quick_main")(FakeParsingToolCall(view))
    assert result["method"] == "entry-arg"
    assert result["main"] == "0x401200"
    assert result["function"] == {
        "start": "0x401200",
        "name": "main_outer",
        "also_containing": [{"start": "0x401234", "name": "main_inner"}],
        "same_name": [],
    }


def test_quick_main_resolves_a_main_symbol_with_its_containing_and_namesake_functions() -> None:
    entry = FakeFunction("_start", 0x1000, 0x1100, hlil=RenderableText("return"))
    main = FakeFunction("main", 0x401234, 0x401400, hlil=RenderableText("return 0"))
    cold = FakeFunction("main.cold", 0x401200, 0x401300, hlil=RenderableText("return 2"))
    other = FakeFunction("main", 0x402000, 0x402100, hlil=RenderableText("return 1"))
    view = FakeBinaryView(entry_point=0x1000, functions=[other, cold, main, entry])
    result = _tool("rex_quick_main")(FakeParsingToolCall(view))
    assert result["method"] == "symbol"
    assert result["main"] == "0x401234"
    assert result["function"] == {
        "start": "0x401234",
        "name": "main",
        "also_containing": [{"start": "0x401200", "name": "main.cold"}],
        "same_name": [{"start": "0x402000", "name": "main"}],
    }
