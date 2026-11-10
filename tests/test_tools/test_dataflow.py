from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from helpers import FakeToolError, _call, get_tool
from helpers_dataflow import (
    FakeHLIL,
    FakeInstruction,
    FakeMLILInstructions,
    add,
    branch,
    compare,
    const,
    load,
    set_var,
    sign_extend,
    var,
)
from helpers_uidf import FakeVariable
from helpers_view import FakeBinaryView, FakeFunction

from binja_plugin.tools import dataflow as dataflow_tools


def _check_view() -> tuple[FakeBinaryView, FakeFunction, FakeVariable, FakeVariable]:
    arg2 = FakeVariable("arg2")
    arg_40 = FakeVariable("arg_40")
    r14 = FakeVariable("r14")
    mlil = FakeMLILInstructions(
        instructions=[
            # if (sx.q(*arg2) != 'p')
            branch(
                0x1010,
                compare(
                    "MLIL_CMP_NE",
                    sign_extend(load(var(arg2))),
                    const(0x70),
                ),
            ),
            # if (sx.q(arg2[0x11]) ... stored in arg_40, then arg_40 != 'h'
            set_var(0x1020, arg_40, sign_extend(load(add(var(arg2), const(0x11))))),
            branch(
                0x1030,
                compare("MLIL_CMP_NE", var(arg_40), const(0x68)),
            ),
            # A branch on two constants folds away and must not be reported.
            branch(0x1040, compare("MLIL_CMP_E", const(1), const(1))),
            # if (r14 == 0x41) where r14 is defined by a load from r14 itself: a variable
            # subject with no definition load.
            branch(0x1050, compare("MLIL_CMP_E", var(r14), const(0x41))),
        ],
        definitions={
            arg_40: [
                set_var(0x1020, arg_40, sign_extend(load(add(var(arg2), const(0x11))))),
            ],
            r14: [set_var(0x1000, r14, const(7))],
        },
        uses={arg_40: [], r14: []},
    )
    function = FakeFunction("check", 0x1000, 0x1100, mlil=mlil, hlil=None)
    view = FakeBinaryView(functions=[function])
    return view, function, arg2, arg_40


def test_constraints_report_the_compared_load_and_constant() -> None:
    view, _, _, _ = _check_view()
    _, constraints = get_tool("rex_function_constraints")
    result = constraints(_call(view), function=0x1000)
    first = result["constraints"][0]
    assert first["address"] == "0x1010"
    assert first["operator"] == "!="
    assert first["constant"] == "0x70"
    assert first["char"] == "p"
    assert first["subject"] == {"kind": "load", "base": "arg2", "offset": "0x0"}


def test_constraints_follow_a_variable_back_to_its_defining_load() -> None:
    view, _, _, _ = _check_view()
    _, constraints = get_tool("rex_function_constraints")
    rows = constraints(_call(view), function=0x1000)["constraints"]
    stored = next(row for row in rows if row["address"] == "0x1030")
    assert stored["subject"]["kind"] == "variable"
    assert stored["subject"]["variable"] == "arg_40"
    assert stored["subject"]["definition"] == {
        "address": "0x1020",
        "load": {"kind": "load", "base": "arg2", "offset": "0x11"},
    }
    assert stored["char"] == "h"


def test_constraints_skip_constant_only_branches_and_keep_plain_variables() -> None:
    view, _, _, _ = _check_view()
    _, constraints = get_tool("rex_function_constraints")
    result = constraints(_call(view), function=0x1000)
    assert [row["address"] for row in result["constraints"]] == ["0x1010", "0x1030", "0x1050"]
    plain = result["constraints"][2]
    assert plain["subject"] == {"kind": "variable", "variable": "r14"}
    assert result["total"] == 3
    assert result["truncated"] is False


def test_constraints_page_with_exact_total() -> None:
    view, _, _, _ = _check_view()
    _, constraints = get_tool("rex_function_constraints")
    page = constraints(_call(view), function=0x1000, limit=2, offset=1)
    assert [row["address"] for row in page["constraints"]] == ["0x1030", "0x1050"]
    assert page["total"] == 3
    assert page["truncated"] is False
    first_page = constraints(_call(view), function=0x1000, limit=1)
    assert first_page["truncated"] is True


def test_constraints_without_mlil_fail_with_no_mlil() -> None:
    function = FakeFunction("bare", 0x2000, 0x2100)
    view = FakeBinaryView(functions=[function])
    _, constraints = get_tool("rex_function_constraints")
    with pytest.raises(FakeToolError) as error:
        constraints(_call(view), function=0x2000)
    assert error.value.code == "no_mlil"
    assert "run bn_analysis_update_and_wait" in error.value.message


def test_hlil_statements_carry_their_addresses() -> None:
    hlil = FakeHLIL(
        [
            [
                _statement(0x1000, 0, "i = 0"),
                _statement(0x1004, 1, "return i"),
            ],
            [_statement(0x1010, 2, "return 1")],
        ]
    )
    function = FakeFunction("main", 0x1000, 0x1100, hlil=hlil)
    view = FakeBinaryView(functions=[function])
    _, statements = get_tool("rex_hlil_statements")
    result = statements(_call(view), function=0x1000, limit=2, offset=1)
    assert result["statements"] == [
        {"address": "0x1004", "index": 1, "text": "return i"},
        {"address": "0x1010", "index": 2, "text": "return 1"},
    ]
    assert result["total"] == 3
    assert result["truncated"] is False
    first_page = statements(_call(view), function=0x1000, limit=2)
    assert first_page["truncated"] is True


def test_hlil_statements_page_past_the_end_keeps_the_exact_total() -> None:
    # The in-repo counterpart of the core's bn_function_disassembly, whose past-end page
    # reports an empty listing: here the page is empty but `total` stays exact, so an
    # out-of-range offset is detectable and must never read as an empty function.
    hlil = FakeHLIL([[_statement(0x1000, 0, "i = 0"), _statement(0x1004, 1, "return i")]])
    function = FakeFunction("main", 0x1000, 0x1100, hlil=hlil)
    view = FakeBinaryView(functions=[function])
    _, statements = get_tool("rex_hlil_statements")
    result = statements(_call(view), function=0x1000, limit=10, offset=5)
    assert result == {
        "function": {"start": "0x1000", "name": "main"},
        "total": 2,
        "truncated": False,
        "statements": [],
    }


def test_hlil_statements_without_hlil_fail_with_no_hlil() -> None:
    function = FakeFunction("bare", 0x2000, 0x2100)
    view = FakeBinaryView(functions=[function])
    _, statements = get_tool("rex_hlil_statements")
    with pytest.raises(FakeToolError) as error:
        statements(_call(view), function=0x2000)
    assert error.value.code == "no_hlil"
    assert "run bn_analysis_update_and_wait" in error.value.message


def _statement(address: int, index: int, text: str) -> FakeInstruction:
    return FakeInstruction("MLIL_NOP", address, instr_index=index, text=text)


def _uses_view(
    instructions: list[FakeInstruction],
    definitions: dict[FakeVariable, list[FakeInstruction]],
    uses: dict[FakeVariable, list[FakeInstruction]] | None = None,
) -> FakeBinaryView:
    mlil = FakeMLILInstructions(instructions, uses=uses, definitions=definitions)
    return FakeBinaryView(functions=[FakeFunction("check", 0x1000, 0x1100, mlil=mlil)])


def _read_of(variable: FakeVariable, address: int = 0x1030) -> FakeInstruction:
    return branch(address, compare("MLIL_CMP_NE", var(variable), const(0x68)))


def _run_uses(view: FakeBinaryView, **arguments: Any) -> dict[str, Any]:
    _, uses = get_tool("rex_mlil_uses")
    arguments.setdefault("function", 0x1000)
    arguments.setdefault("address", 0x1020)
    return uses(_call(view), **arguments)


def _no_uses_report(name: str, definitions: list[str]) -> dict[str, Any]:
    return {
        "variable": name,
        "definitions": definitions,
        "total": 0,
        "truncated": False,
        "uses": [],
    }


def _two_use_view() -> FakeBinaryView:
    arg_40 = FakeVariable("arg_40")
    use_branch = _read_of(arg_40, 0x1030)
    copy = FakeVariable("tmp")
    use_copy = set_var(0x1040, copy, var(arg_40))
    definition = set_var(
        0x1020, arg_40, sign_extend(load(add(var(FakeVariable("arg2")), const(0x11))))
    )
    return _uses_view(
        [definition, use_branch, use_copy],
        definitions={arg_40: [definition], copy: [use_copy]},
        uses={arg_40: [use_copy, use_branch]},
    )


def test_uses_report_the_exact_response_for_a_single_assignment() -> None:
    assert _run_uses(_two_use_view()) == {
        "function": {"start": "0x1000", "name": "check"},
        "definition_site": "0x1020",
        "variables": [
            {
                "variable": "arg_40",
                "definitions": ["0x1020"],
                "total": 2,
                "truncated": False,
                "uses": [
                    {
                        "address": "0x1030",
                        "operation": "MLIL_IF",
                        "text": "MLIL_IF",
                    },
                    {
                        "address": "0x1040",
                        "operation": "MLIL_SET_VAR",
                        "text": "tmp = arg_40",
                    },
                ],
            }
        ],
    }


@pytest.mark.parametrize(
    ("limit", "offset", "addresses", "truncated"),
    [
        (1, 0, ["0x1030"], True),
        (2, 0, ["0x1030", "0x1040"], False),
        (1, 1, ["0x1040"], False),
        (1, 2, [], False),
        (0, 0, [], True),
    ],
)
def test_uses_page_each_variable_and_flag_truncation(
    limit: int, offset: int, addresses: list[str], truncated: bool
) -> None:
    report = _run_uses(_two_use_view(), limit=limit, offset=offset)["variables"][0]
    assert [row["address"] for row in report["uses"]] == addresses
    assert report["truncated"] is truncated
    assert report["total"] == 2


def test_uses_page_every_defined_variable_independently() -> None:
    high, low = FakeVariable("high"), FakeVariable("low")
    split = FakeInstruction("MLIL_SET_VAR_SPLIT", 0x1020, high=high, low=low, src=const(1))
    view = _uses_view(
        [split, _read_of(high, 0x1030), _read_of(high, 0x1040), _read_of(low, 0x1050)],
        definitions={high: [split], low: [split]},
        uses={high: [_read_of(high, 0x1030), _read_of(high, 0x1040)], low: [_read_of(low, 0x1050)]},
    )
    reports = _run_uses(view, limit=1, offset=1)["variables"]
    assert [(r["variable"], r["total"], r["truncated"]) for r in reports] == [
        ("high", 2, False),
        ("low", 1, False),
    ]
    assert [[row["address"] for row in r["uses"]] for r in reports] == [["0x1040"], []]


def test_uses_reject_an_address_that_defines_nothing() -> None:
    with pytest.raises(FakeToolError) as error:
        _run_uses(_two_use_view(), address=0x1030)
    assert error.value.code == "no_definition"
    assert error.value.message == (
        "no MLIL variable definition at 0x1030 in check; "
        "variables are defined at: 0x1020, 0x1040; "
        "use rex_hlil_statements or bn_function_il to match an address to its variable"
    )


def test_uses_report_a_field_write_the_core_records_though_vars_written_is_empty() -> None:
    holder = FakeVariable("holder")
    definition = FakeInstruction(
        "MLIL_SET_VAR_FIELD", 0x1020, dest=holder, src=load(var(FakeVariable("arg2"))), offset=8
    )
    assert definition.vars_written == []
    view = _uses_view(
        [definition, _read_of(holder)],
        definitions={holder: [definition]},
        uses={holder: [_read_of(holder)]},
    )
    reports = _run_uses(view)["variables"]
    assert [(r["variable"], r["definitions"], r["total"]) for r in reports] == [
        ("holder", ["0x1020"], 1)
    ]


def test_uses_report_both_halves_of_a_split_write_high_first() -> None:
    high, low = FakeVariable("high"), FakeVariable("low")
    split = FakeInstruction("MLIL_SET_VAR_SPLIT", 0x1020, high=high, low=low, src=const(1))
    view = _uses_view(
        [split, _read_of(low)],
        definitions={low: [split], high: [split]},
        uses={low: [_read_of(low)]},
    )
    assert _run_uses(view)["variables"] == [
        _no_uses_report("high", ["0x1020"]),
        {
            **_no_uses_report("low", ["0x1020"]),
            "total": 1,
            "uses": [{"address": "0x1030", "operation": "MLIL_IF", "text": "MLIL_IF"}],
        },
    ]


@pytest.mark.parametrize(
    "operation", ["MLIL_CALL", "MLIL_CALL_UNTYPED", "MLIL_SYSCALL", "MLIL_SYSCALL_UNTYPED"]
)
def test_uses_report_a_call_output_as_the_definition(operation: str) -> None:
    rax = FakeVariable("rax")
    call = FakeInstruction(operation, 0x1020, output=[rax])
    view = _uses_view([call, _read_of(rax)], {rax: [call]}, {rax: [_read_of(rax)]})
    reports = _run_uses(view)["variables"]
    assert [(r["variable"], r["definitions"], r["total"]) for r in reports] == [
        ("rax", ["0x1020"], 1)
    ]


@pytest.mark.parametrize("operation", ["MLIL_CALL", "MLIL_TAILCALL", "MLIL_INTRINSIC"])
def test_uses_report_every_output_of_a_multi_output_instruction(operation: str) -> None:
    rax, rcx, rdx = FakeVariable("rax"), FakeVariable("rcx"), FakeVariable("rdx")
    call = FakeInstruction(operation, 0x1020, output=[rax, rcx, rdx])
    view = _uses_view([call], {rdx: [call], rax: [call], rcx: [call]})
    assert _run_uses(view)["variables"] == [
        _no_uses_report("rax", ["0x1020"]),
        _no_uses_report("rcx", ["0x1020"]),
        _no_uses_report("rdx", ["0x1020"]),
    ]


def test_uses_accept_a_tailcall_clobber_as_a_definition_site() -> None:
    rax = FakeVariable("rax")
    tailcall = FakeInstruction("MLIL_TAILCALL", 0x1020, output=[rax])
    assert _run_uses(_uses_view([tailcall], {rax: [tailcall]}))["variables"] == [
        _no_uses_report("rax", ["0x1020"])
    ]


def test_uses_report_a_forced_version_as_a_definition() -> None:
    zmm0 = FakeVariable("zmm0_1")
    forced = FakeInstruction("MLIL_FORCE_VER", 0x1020, dest=zmm0)
    assert _run_uses(_uses_view([forced], {zmm0: [forced]}))["variables"] == [
        _no_uses_report("zmm0_1", ["0x1020"])
    ]


@pytest.mark.parametrize(
    "instruction",
    [
        FakeInstruction("MLIL_CALL", 0x1020, output=[]),
        FakeInstruction("MLIL_TAILCALL", 0x1020, output=[]),
        FakeInstruction("MLIL_STORE", 0x1020),
        FakeInstruction("MLIL_RET", 0x1020),
    ],
)
def test_uses_reject_an_instruction_the_core_defines_nothing_at(
    instruction: FakeInstruction,
) -> None:
    other = FakeVariable("other")
    elsewhere = set_var(0x1010, other, const(1))
    view = _uses_view([elsewhere, instruction], {other: [elsewhere]})
    with pytest.raises(FakeToolError) as error:
        _run_uses(view)
    assert error.value.code == "no_definition"
    assert error.value.message == (
        "no MLIL variable definition at 0x1020 in check; "
        "variables are defined at: 0x1010; "
        "use rex_hlil_statements or bn_function_il to match an address to its variable"
    )


def test_uses_follow_the_core_recorded_definitions_not_the_operation_name() -> None:
    rax = FakeVariable("rax")
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[rax])
    with pytest.raises(FakeToolError) as error:
        _run_uses(_uses_view([call], {}))
    assert error.value.code == "no_definition"


def test_uses_order_variables_by_vars_written_then_by_core_record() -> None:
    rax, rcx, extra = FakeVariable("rax"), FakeVariable("rcx"), FakeVariable("extra")
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[rax, rcx])
    view = _uses_view([call], {extra: [call], rcx: [call], rax: [call]})
    assert [r["variable"] for r in _run_uses(view)["variables"]] == ["rax", "rcx", "extra"]


def test_uses_exclude_a_written_variable_the_core_records_no_definition_for() -> None:
    rax, rcx = FakeVariable("rax"), FakeVariable("rcx")
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[rax, rcx])
    view = _uses_view([call], {rax: [call]}, uses={rcx: []})
    assert [r["variable"] for r in _run_uses(view)["variables"]] == ["rax"]


def test_uses_list_a_field_written_variable_once_when_the_core_records_it_twice() -> None:
    holder = FakeVariable("holder")
    field = FakeInstruction("MLIL_SET_VAR_FIELD", 0x1020, dest=holder, src=const(1), offset=0)
    view = _uses_view([field], {holder: [field, field]})
    assert [r["variable"] for r in _run_uses(view)["variables"]] == ["holder"]


def test_uses_list_a_variable_once_when_two_instructions_at_an_address_define_it() -> None:
    holder = FakeVariable("holder")
    low = FakeInstruction("MLIL_SET_VAR_FIELD", 0x1020, dest=holder, src=const(1), offset=0)
    high = FakeInstruction("MLIL_SET_VAR_FIELD", 0x1020, dest=holder, src=const(2), offset=4)
    view = _uses_view([low, high], {holder: [low, high]})
    assert [r["variable"] for r in _run_uses(view)["variables"]] == ["holder"]


def test_uses_merge_the_variables_of_every_instruction_at_one_address() -> None:
    first, second = FakeVariable("first"), FakeVariable("second")
    write_first = set_var(0x1020, first, const(1))
    write_second = set_var(0x1020, second, const(2))
    view = _uses_view([write_first, write_second], {first: [write_first], second: [write_second]})
    assert [r["variable"] for r in _run_uses(view)["variables"]] == ["first", "second"]


def test_uses_do_not_attribute_definitions_of_other_instructions() -> None:
    first, second = FakeVariable("first"), FakeVariable("second")
    write_first = set_var(0x1020, first, const(1))
    write_second = set_var(0x1030, second, const(2))
    view = _uses_view([write_first, write_second], {first: [write_first], second: [write_second]})
    assert [r["variable"] for r in _run_uses(view)["variables"]] == ["first"]


def test_uses_filter_to_the_named_defined_variable() -> None:
    rax, rcx = FakeVariable("rax"), FakeVariable("rcx")
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[rax, rcx])
    view = _uses_view([call], {rax: [call], rcx: [call]})
    assert _run_uses(view, variable="rcx")["variables"] == [_no_uses_report("rcx", ["0x1020"])]


def test_uses_filter_by_exact_name_not_prefix() -> None:
    rax, rcx = FakeVariable("rax"), FakeVariable("rcx")
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[rax, rcx])
    view = _uses_view([call], {rax: [call], rcx: [call]})
    with pytest.raises(FakeToolError) as error:
        _run_uses(view, variable="r")
    assert error.value.code == "no_variable"


def test_uses_reject_a_variable_not_defined_at_the_address() -> None:
    rax, rcx = FakeVariable("rax"), FakeVariable("rcx")
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[rax, rcx])
    view = _uses_view([call], {rax: [call], rcx: [call]})
    with pytest.raises(FakeToolError) as error:
        _run_uses(view, variable="rdx")
    assert error.value.code == "no_variable"
    assert error.value.message == (
        "no variable named 'rdx' is defined at 0x1020 in check; defined there: rax, rcx"
    )


def test_uses_list_a_call_output_site_among_the_defined_variable_sites() -> None:
    rax = FakeVariable("rax")
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[rax])
    with pytest.raises(FakeToolError) as error:
        _run_uses(_uses_view([call], {rax: [call]}), address=0x1030)
    assert "variables are defined at: 0x1020;" in error.value.message


def test_uses_missing_definition_counts_sites_past_the_listed_ones() -> None:
    definitions = [
        set_var(0x1100 + index * 0x10, FakeVariable(f"v{index}"), const(index))
        for index in range(12)
    ]
    recorded = {definition.dest: [definition] for definition in definitions}
    mlil = FakeMLILInstructions(definitions, definitions=recorded)
    function = FakeFunction("check", 0x1000, 0x1200, mlil=mlil)
    view = FakeBinaryView(functions=[function])
    _, uses = get_tool("rex_mlil_uses")
    with pytest.raises(FakeToolError) as error:
        uses(_call(view), function=0x1000, address=0x1030)
    assert error.value.code == "no_definition"
    assert error.value.message == (
        "no MLIL variable definition at 0x1030 in check; "
        "variables are defined at: 0x1100, 0x1110, 0x1120, 0x1130, 0x1140, 0x1150, "
        "0x1160, 0x1170, 0x1180, 0x1190 (+2 more); "
        "use rex_hlil_statements or bn_function_il to match an address to its variable"
    )


def test_module_exposes_the_registered_tools() -> None:
    assert dataflow_tools.rex_function_constraints is not None
    assert dataflow_tools.rex_hlil_statements is not None
    assert dataflow_tools.rex_mlil_uses is not None
    assert dataflow_tools.rex_parameter_variables is not None


def test_constraints_describe_the_remaining_subject_shapes() -> None:
    arg2 = FakeVariable("arg2")
    value = FakeVariable("value")
    other = FakeVariable("other")
    mlil = FakeMLILInstructions(
        instructions=[
            # Subject is a load through a computed pointer, not var + constant.
            branch(
                0x2010,
                compare(
                    "MLIL_CMP_NE",
                    load(add(load(var(arg2)), const(4))),
                    const(0x41),
                ),
            ),
            # Subject is arithmetic on a variable, not a load.
            branch(0x2020, compare("MLIL_CMP_E", add(var(value), const(1)), const(0x42))),
            # A branch on a bare truth value compares nothing.
            branch(0x2050, var(other)),
            # Absolute address load, folded to its constant offset.
            branch(0x2060, compare("MLIL_CMP_E", load(const(0x403198)), const(0x70))),
            # Neither side is constant, so no constraint is stated.
            branch(0x2030, compare("MLIL_CMP_E", var(value), var(other))),
            # Subject variable has two definitions, so no single defining load is named.
            branch(0x2040, compare("MLIL_CMP_E", var(value), const(0x43))),
            # The constant on the left reads the same as on the right.
            branch(0x2070, compare("MLIL_CMP_E", const(0x44), var(other))),
        ],
        definitions={
            value: [
                set_var(0x2000, value, load(var(arg2))),
                set_var(0x2004, value, const(0)),
            ],
        },
    )
    function = FakeFunction("shapes", 0x2000, 0x2100, mlil=mlil)
    view = FakeBinaryView(functions=[function])
    _, constraints = get_tool("rex_function_constraints")
    rows = constraints(_call(view), function=0x2000)["constraints"]
    assert [row["address"] for row in rows] == [
        "0x2010",
        "0x2020",
        "0x2040",
        "0x2060",
        "0x2070",
    ]
    assert rows[3]["subject"] == {"kind": "load", "base": None, "offset": "0x403198"}
    assert rows[0]["subject"] == {
        "kind": "load",
        "base": None,
        "offset": None,
        "text": "*(arg2) + 0x4",
    }
    assert rows[1]["subject"] == {"kind": "expression", "text": "value + 0x1"}
    assert rows[2]["subject"] == {"kind": "variable", "variable": "value"}
    assert rows[4] == {
        "address": "0x2070",
        "operator": "==",
        "constant": "0x44",
        "char": "D",
        "subject": {"kind": "variable", "variable": "other"},
        "subject_text": "other",
    }


def test_constraints_char_prints_only_printable_constants() -> None:
    # The char field maps constants in [0x20, 0x7F) to their character: 0x20 (space) is
    # the printable floor, 0x7F (DEL) and above report None.
    arg2 = FakeVariable("arg2")
    mlil = FakeMLILInstructions(
        instructions=[
            branch(0x3010, compare("MLIL_CMP_NE", var(arg2), const(0x20))),
            branch(0x3020, compare("MLIL_CMP_NE", var(arg2), const(0x7F))),
            branch(0x3030, compare("MLIL_CMP_NE", var(arg2), const(0x2010))),
        ],
    )
    function = FakeFunction("chars", 0x3000, 0x3100, mlil=mlil)
    view = FakeBinaryView(functions=[function])
    _, constraints = get_tool("rex_function_constraints")
    rows = constraints(_call(view), function=0x3000)["constraints"]
    assert [row["char"] for row in rows] == [" ", None, None]


def test_uses_without_mlil_fail_with_no_mlil() -> None:
    function = FakeFunction("bare", 0x2000, 0x2100)
    view = FakeBinaryView(functions=[function])
    _, uses = get_tool("rex_mlil_uses")
    with pytest.raises(FakeToolError) as error:
        uses(_call(view), function=0x2000, address=0x2004)
    assert error.value.code == "no_mlil"
    assert "run bn_analysis_update_and_wait" in error.value.message


def test_parameter_maps_to_the_copies_that_carry_it() -> None:
    arg4 = FakeVariable("arg4")
    arg4.storage = 112
    arg4.source_type = type("Source", (), {"name": "StackVariableSourceType"})()
    r14 = FakeVariable("r14")
    mlil = FakeMLILInstructions(
        instructions=[
            set_var(0x1438, r14, var(arg4)),
            set_var(0x1450, FakeVariable("tmp"), load(var(r14))),
            branch(0x1460, var(r14)),
        ],
        definitions={r14: [set_var(0x1438, r14, var(arg4))]},
    )
    function = FakeFunction("check", 0x1000, 0x1100, mlil=mlil, vars=[arg4, r14])
    view = FakeBinaryView(functions=[function])
    _, parameter = get_tool("rex_parameter_variables")
    result = parameter(_call(view), function=0x1000, parameter="arg4")
    assert result["storage"] == [{"source": "StackVariableSourceType", "storage": 112}]
    assert result["carriers"] == [{"variable": "r14", "address": "0x1438", "text": "r14 = arg4"}]


def test_parameter_without_a_name_match_lists_candidates() -> None:
    function = FakeFunction(
        "check", 0x1000, 0x1100, mlil=FakeMLILInstructions([]), vars=[FakeVariable("arg2")]
    )
    view = FakeBinaryView(functions=[function])
    _, parameter = get_tool("rex_parameter_variables")
    with pytest.raises(FakeToolError) as error:
        parameter(_call(view), function=0x1000, parameter="arg9")
    assert error.value.code == "no_variable"
    assert "arg2" in error.value.message


def test_parameter_missing_name_counts_candidates_past_the_listed_ones() -> None:
    variables = [FakeVariable(f"arg{index}") for index in range(41)]
    function = FakeFunction("check", 0x1000, 0x1100, mlil=FakeMLILInstructions([]), vars=variables)
    view = FakeBinaryView(functions=[function])
    _, parameter = get_tool("rex_parameter_variables")
    with pytest.raises(FakeToolError) as error:
        parameter(_call(view), function=0x1000, parameter="arg9x")
    assert error.value.code == "no_variable"
    assert error.value.message.endswith(
        "(+1 more); use bn_variable_list for the full list. "
        "Register-allocated parameters are named by their register (for example r14), "
        "not by their argument name"
    )


def test_parameter_without_mlil_fails_with_no_mlil() -> None:
    function = FakeFunction("bare", 0x2000, 0x2100, vars=[FakeVariable("arg2")])
    view = FakeBinaryView(functions=[function])
    _, parameter = get_tool("rex_parameter_variables")
    with pytest.raises(FakeToolError) as error:
        parameter(_call(view), function=0x2000, parameter="arg2")
    assert error.value.code == "no_mlil"
    assert "run bn_analysis_update_and_wait" in error.value.message


class _BareVariable:
    """Mirrors a register variable: no source_type or storage attribute at all."""

    def __init__(self, name: str) -> None:
        self.name = name


def test_parameter_storage_covers_variables_without_source_metadata() -> None:
    # A variable with no source_type falls back to str(None), and a source type without a
    # .name attribute still renders as its own string form.
    bare = _BareVariable("reg9")
    nameless = FakeVariable("reg9")
    nameless.source_type = 42
    function = FakeFunction(
        "check",
        0x1000,
        0x1100,
        mlil=FakeMLILInstructions([]),
        vars=[bare, nameless],  # ty: ignore[invalid-argument-type] register vars lack the slots
    )
    view = FakeBinaryView(functions=[function])
    _, parameter = get_tool("rex_parameter_variables")
    result = parameter(_call(view), function=0x1000, parameter="reg9")
    assert result["storage"] == [
        {"source": "None", "storage": None},
        {"source": "42", "storage": 0},
    ]


def test_parameter_carriers_scan_the_whole_function_and_sort_by_address() -> None:
    # The scan must move past definitions whose source is not the parameter and past
    # non-definition instructions, and the report sorts carriers by address.
    arg4 = FakeVariable("arg4")
    r14 = FakeVariable("r14")
    r15 = FakeVariable("r15")
    mlil = FakeMLILInstructions(
        instructions=[
            set_var(0x1010, FakeVariable("tmp"), load(var(arg4))),
            branch(0x1020, var(arg4)),
            set_var(0x1400, r14, var(arg4)),
            set_var(0x1040, r15, var(arg4)),
        ],
    )
    function = FakeFunction("check", 0x1000, 0x1100, mlil=mlil, vars=[arg4, r14, r15])
    view = FakeBinaryView(functions=[function])
    _, parameter = get_tool("rex_parameter_variables")
    result = parameter(_call(view), function=0x1000, parameter="arg4")
    assert result["carriers"] == [
        {"variable": "r15", "address": "0x1040", "text": "r15 = arg4"},
        {"variable": "r14", "address": "0x1400", "text": "r14 = arg4"},
    ]


def test_uses_render_a_use_whose_operation_has_no_name_attribute() -> None:
    # An operation object without .name must render as its string form, not raise or
    # report None.
    arg_40 = FakeVariable("arg_40")
    definition = set_var(0x1020, arg_40, const(1))
    use = SimpleNamespace(operation=42, address=0x1030)
    mlil = FakeMLILInstructions(
        instructions=[definition],
        definitions={arg_40: [definition]},
        uses={arg_40: [use]},  # ty: ignore[invalid-argument-type]
    )
    function = FakeFunction("check", 0x1000, 0x1100, mlil=mlil)
    view = FakeBinaryView(functions=[function])
    _, uses = get_tool("rex_mlil_uses")
    result = uses(_call(view), function=0x1000, address=0x1020)
    assert result["variables"][0]["uses"][0]["operation"] == "42"
