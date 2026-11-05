from __future__ import annotations

from types import SimpleNamespace

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


def _uses_view() -> tuple[FakeBinaryView, FakeVariable]:
    arg_40 = FakeVariable("arg_40")
    use_branch = branch(0x1030, compare("MLIL_CMP_NE", var(arg_40), const(0x68)))
    use_return = set_var(0x1040, FakeVariable("tmp"), var(arg_40))
    definition = set_var(
        0x1020, arg_40, sign_extend(load(add(var(FakeVariable("arg2")), const(0x11))))
    )
    mlil = FakeMLILInstructions(
        instructions=[definition, use_branch, use_return],
        definitions={arg_40: [definition]},
        uses={arg_40: [use_branch, use_return]},
    )
    function = FakeFunction("check", 0x1000, 0x1100, mlil=mlil)
    return FakeBinaryView(functions=[function]), arg_40


def test_uses_list_every_read_of_the_defined_variable() -> None:
    view, _ = _uses_view()
    _, uses = get_tool("rex_mlil_uses")
    result = uses(_call(view), function=0x1000, address=0x1020)
    assert result["variable"] == "arg_40"
    assert result["definition_site"] == "0x1020"
    assert result["definitions"] == ["0x1020"]
    assert [row["address"] for row in result["uses"]] == ["0x1030", "0x1040"]
    assert result["total"] == 2
    assert result["truncated"] is False


def test_uses_page_and_flag_truncation() -> None:
    view, _ = _uses_view()
    _, uses = get_tool("rex_mlil_uses")
    result = uses(_call(view), function=0x1000, address=0x1020, limit=1)
    assert [row["address"] for row in result["uses"]] == ["0x1030"]
    assert result["truncated"] is True


def test_uses_reject_an_address_that_defines_nothing() -> None:
    view, _ = _uses_view()
    _, uses = get_tool("rex_mlil_uses")
    with pytest.raises(FakeToolError) as error:
        uses(_call(view), function=0x1000, address=0x1030)
    assert error.value.code == "no_definition"
    assert error.value.message == (
        "no MLIL variable definition at 0x1030 in check; "
        "variables are defined at: 0x1020, 0x1040; "
        "use rex_hlil_statements or bn_function_il to match an address to its variable"
    )


def test_uses_accept_a_field_write_as_the_definition_site() -> None:
    # A struct member write (MLIL_SET_VAR_FIELD) defines its dest variable, so its address
    # must resolve like any other assignment instead of missing the variable.
    arg2 = FakeVariable("arg2")
    holder = FakeVariable("holder")
    definition = FakeInstruction(
        "MLIL_SET_VAR_FIELD", 0x1020, dest=holder, src=load(var(arg2)), offset=8
    )
    use = branch(0x1030, compare("MLIL_CMP_NE", var(holder), const(0x68)))
    mlil = FakeMLILInstructions(
        instructions=[definition, use],
        definitions={holder: [definition]},
        uses={holder: [use]},
    )
    function = FakeFunction("check", 0x1000, 0x1100, mlil=mlil)
    view = FakeBinaryView(functions=[function])
    _, uses = get_tool("rex_mlil_uses")
    result = uses(_call(view), function=0x1000, address=0x1020)
    assert result["variable"] == "holder"
    assert result["definitions"] == ["0x1020"]
    assert [row["address"] for row in result["uses"]] == ["0x1030"]


def test_uses_resolve_a_split_write_to_its_high_variable() -> None:
    # A split write (MLIL_SET_VAR_SPLIT) defines a high:low pair at one site and has no
    # dest operand; the high half is the variable the tool reports.
    high = FakeVariable("high")
    low = FakeVariable("low")
    split = FakeInstruction("MLIL_SET_VAR_SPLIT", 0x1020, high=high, low=low, src=const(1))
    use = branch(0x1030, compare("MLIL_CMP_NE", var(high), const(0x68)))
    mlil = FakeMLILInstructions(
        instructions=[split, use],
        definitions={high: [split], low: [split]},
        uses={high: [use]},
    )
    function = FakeFunction("check", 0x1000, 0x1100, mlil=mlil)
    view = FakeBinaryView(functions=[function])
    _, uses = get_tool("rex_mlil_uses")
    result = uses(_call(view), function=0x1000, address=0x1020)
    assert result["variable"] == "high"
    assert result["definitions"] == ["0x1020"]
    assert [row["address"] for row in result["uses"]] == ["0x1030"]


def test_uses_missing_definition_counts_sites_past_the_listed_ones() -> None:
    definitions = [
        set_var(0x1100 + index * 0x10, FakeVariable(f"v{index}"), const(index))
        for index in range(12)
    ]
    function = FakeFunction("check", 0x1000, 0x1200, mlil=FakeMLILInstructions(definitions))
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
        # ty: ignore[invalid-argument-type] the degenerate use is deliberately not a FakeInstruction
        instructions=[definition, use],
        definitions={arg_40: [definition]},
        uses={arg_40: [use]},  # ty: ignore[invalid-argument-type]
    )
    function = FakeFunction("check", 0x1000, 0x1100, mlil=mlil)
    view = FakeBinaryView(functions=[function])
    _, uses = get_tool("rex_mlil_uses")
    result = uses(_call(view), function=0x1000, address=0x1020)
    assert result["uses"][0]["operation"] == "42"
