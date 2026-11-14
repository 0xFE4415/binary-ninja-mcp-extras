from __future__ import annotations

from typing import Any

import pytest
from helpers import (
    NO_ALTERNATIVES,
    FakeTool,
    FakeToolError,
    _call,
    _run_uses,
    _uses_view,
    get_tool,
)
from helpers_dataflow import (
    FakeHLIL,
    FakeInstruction,
    FakeMLILInstructions,
    FakeMLILSSA,
    FakeSSAVariable,
    _flag_variable,
    _stack_variable,
    add,
    branch,
    compare,
    const,
    constant_value,
    load,
    set_var,
    set_var_ssa,
    sign_extend,
    var,
    var_ssa,
    zero_extend,
)
from helpers_uidf import FakeVariable, FakeVariableSourceType
from helpers_view import (
    SKIP_CAUSES,
    FakeAnalysisSkipReason,
    FakeArchitecture,
    FakeBinaryView,
    FakeFunction,
)

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
        "function": {"start": "0x1000", "name": "main", **NO_ALTERNATIVES},
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


_MISSING_IL_SITES = [
    pytest.param("rex_function_constraints", {}, "no_mlil", "MediumLevelIL", id="constraints"),
    pytest.param("rex_hlil_statements", {}, "no_hlil", "HLIL", id="hlil_statements"),
    pytest.param("rex_mlil_uses", {"address": 0x2004}, "no_mlil", "MediumLevelIL", id="uses"),
    pytest.param(
        "rex_parameter_variables", {"parameter": "arg2"}, "no_mlil", "MediumLevelIL", id="parameter"
    ),
    pytest.param(
        "rex_uidf_set", {"variable": "x", "value": "1"}, "no_mlil", "MediumLevelIL", id="uidf_set"
    ),
    pytest.param("rex_uidf_clear", {"variable": "x"}, "no_mlil", "MediumLevelIL", id="uidf_clear"),
]


def _call_missing_il_site(
    tool_name: str, arguments: dict[str, Any], function: FakeFunction
) -> FakeToolError:
    _, tool = get_tool(tool_name)
    with pytest.raises(FakeToolError) as error:
        tool(_call(FakeBinaryView(functions=[function])), function=0x2000, **arguments)
    return error.value


def test_skip_causes_cover_every_skip_reason() -> None:
    assert set(SKIP_CAUSES) == set(FakeAnalysisSkipReason)


@pytest.mark.parametrize(("tool_name", "arguments", "code", "level"), _MISSING_IL_SITES)
def test_a_function_with_analysis_pending_is_told_to_wait(
    tool_name: str, arguments: dict[str, Any], code: str, level: str
) -> None:
    error = _call_missing_il_site(
        tool_name, arguments, FakeFunction("bare", 0x2000, 0x2100, vars=[FakeVariable("x")])
    )
    assert error.code == code
    assert error.message == (
        f"function bare has no {level} yet; "
        "run bn_analysis_update_and_wait (or rex_analysis_wait with a bound) and retry"
    )


@pytest.mark.parametrize(("tool_name", "arguments", "code", "level"), _MISSING_IL_SITES)
def test_a_skipped_function_is_not_told_to_wait(
    tool_name: str, arguments: dict[str, Any], code: str, level: str
) -> None:
    function = FakeFunction(
        "bare",
        0x2000,
        0x2100,
        vars=[FakeVariable("x")],
        analysis_skipped=True,
        analysis_skip_reason=FakeAnalysisSkipReason.AlwaysSkipReason,
    )
    error = _call_missing_il_site(tool_name, arguments, function)
    assert error.code == code
    assert error.message == (
        f"function bare has no {level}: its analysis is skipped "
        "(its analysis_skip_override always skips it); "
        "waiting for analysis will not produce one"
    )


@pytest.mark.parametrize("reason", list(FakeAnalysisSkipReason), ids=lambda reason: reason.name)
def test_a_skipped_function_reports_the_core_skip_reason(reason: FakeAnalysisSkipReason) -> None:
    function = FakeFunction(
        "bare", 0x2000, 0x2100, analysis_skipped=True, analysis_skip_reason=reason
    )
    error = _call_missing_il_site("rex_function_constraints", {}, function)
    assert error.message == (
        f"function bare has no MediumLevelIL: its analysis is skipped ({SKIP_CAUSES[reason]}); "
        "waiting for analysis will not produce one"
    )


@pytest.mark.parametrize("reason", list(FakeAnalysisSkipReason), ids=lambda reason: reason.name)
def test_a_reason_without_a_skip_does_not_stop_the_wait_advice(
    reason: FakeAnalysisSkipReason,
) -> None:
    function = FakeFunction(
        "bare", 0x2000, 0x2100, analysis_skipped=False, analysis_skip_reason=reason
    )
    error = _call_missing_il_site("rex_hlil_statements", {}, function)
    assert error.message == (
        "function bare has no HLIL yet; "
        "run bn_analysis_update_and_wait (or rex_analysis_wait with a bound) and retry"
    )


def test_a_skipped_function_name_is_truncated_in_the_message() -> None:
    function = FakeFunction(
        "n" * 600,
        0x2000,
        0x2100,
        analysis_skipped=True,
        analysis_skip_reason=FakeAnalysisSkipReason.ExceedFunctionSizeSkipReason,
    )
    error = _call_missing_il_site("rex_function_constraints", {}, function)
    assert error.message == (
        f"function {'n' * 512}... [88 chars truncated] has no MediumLevelIL: "
        "its analysis is skipped (it exceeds the analysis.limits.maxFunctionSize limit); "
        "waiting for analysis will not produce one"
    )


def _statement(address: int, index: int, text: str) -> FakeInstruction:
    return FakeInstruction("MLIL_NOP", address, instr_index=index, text=text)


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


def test_parameter_maps_to_the_copies_that_carry_it() -> None:
    arg4 = FakeVariable("arg4")
    arg4.storage = 112
    arg4.source_type = FakeVariableSourceType.StackVariableSourceType
    r14 = FakeVariable("r14")
    copy = set_var_ssa(
        0x1438, FakeSSAVariable(r14, 1), var_ssa(FakeSSAVariable(arg4, 0)), "r14 = arg4"
    )
    ssa = FakeMLILSSA(
        [
            copy,
            set_var_ssa(
                0x1450,
                FakeSSAVariable(FakeVariable("tmp"), 1),
                load(var_ssa(FakeSSAVariable(r14, 1))),
                "tmp = [r14]",
            ),
        ]
    )
    mlil = FakeMLILInstructions(
        instructions=[copy.non_ssa_form, branch(0x1460, var(r14))],
        definitions={r14: [copy.non_ssa_form]},
        ssa_form=ssa,
    )
    function = FakeFunction("check", 0x1000, 0x1100, mlil=mlil, vars=[arg4, r14])
    view = FakeBinaryView(functions=[function])
    _, parameter = get_tool("rex_parameter_variables")
    result = parameter(_call(view), function=0x1000, parameter="arg4")
    assert result["storage"] == [{"source": "stack", "stack_offset": 112}]
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
    assert error.value.message.endswith("(+1 more); use bn_variable_list for the full list")


def test_parameter_missing_name_lists_exactly_the_candidate_cap() -> None:
    variables = [FakeVariable(f"arg{index:02d}") for index in range(41)]
    function = FakeFunction("check", 0x1000, 0x1100, mlil=FakeMLILInstructions([]), vars=variables)
    view = FakeBinaryView(functions=[function])
    _, parameter = get_tool("rex_parameter_variables")
    with pytest.raises(FakeToolError) as error:
        parameter(_call(view), function=0x1000, parameter="nope")
    assert "arg39 (+1 more)" in error.value.message
    assert "arg40" not in error.value.message


def test_parameter_definitions_list_every_definition_of_every_same_named_variable() -> None:
    first = FakeVariable("arg2", storage=105)
    second = FakeVariable("arg2", storage=104)
    mlil = FakeMLILInstructions(
        instructions=[],
        definitions={
            first: [set_var(0x1010, first, const(1)), set_var(0x1020, first, const(2))],
            second: [set_var(0x1030, second, const(3))],
        },
    )
    function = FakeFunction("check", 0x1000, 0x1100, mlil=mlil, vars=[first, second])
    view = FakeBinaryView(functions=[function])
    _, parameter = get_tool("rex_parameter_variables")
    result = parameter(_call(view), function=0x1000, parameter="arg2")
    assert result["definitions"] == ["0x1010", "0x1020", "0x1030"]


def test_parameter_without_mlil_fails_with_no_mlil() -> None:
    function = FakeFunction("bare", 0x2000, 0x2100, vars=[FakeVariable("arg2")])
    view = FakeBinaryView(functions=[function])
    _, parameter = get_tool("rex_parameter_variables")
    with pytest.raises(FakeToolError) as error:
        parameter(_call(view), function=0x2000, parameter="arg2")
    assert error.value.code == "no_mlil"
    assert "run bn_analysis_update_and_wait" in error.value.message


def _parameter_view(*variables: FakeVariable, arch: FakeArchitecture | None = None) -> Any:
    function = FakeFunction(
        "check", 0x1000, 0x1100, mlil=FakeMLILInstructions([]), vars=list(variables), arch=arch
    )
    return FakeBinaryView(functions=[function])


def _parameter_storage(view: FakeBinaryView, name: str) -> list[dict[str, Any]]:
    _, parameter = get_tool("rex_parameter_variables")
    return parameter(_call(view), function=0x1000, parameter=name)["storage"]


@pytest.mark.parametrize(
    ("variable", "storage"),
    [
        (FakeVariable("v", storage=105), {"source": "register", "register": "rdi"}),
        (_stack_variable("v", 8), {"source": "stack", "stack_offset": 8}),
        (_stack_variable("v", -8), {"source": "stack", "stack_offset": -8}),
        (_flag_variable(6), {"source": "flag", "flag": "z"}),
        (_flag_variable(0x80000000), {"source": "flag", "flag": "temp flag 0"}),
        (
            FakeVariable(
                "v", source_type=FakeVariableSourceType.CompositeReturnValueSourceType, storage=3
            ),
            {"source": "composite_return_value", "storage": 3},
        ),
        (
            FakeVariable(
                "v", source_type=FakeVariableSourceType.CompositeParameterSourceType, storage=4
            ),
            {"source": "composite_parameter", "storage": 4},
        ),
    ],
)
def test_parameter_storage_has_the_shape_mlil_uses_reports(
    variable: FakeVariable, storage: dict[str, Any]
) -> None:
    assert _parameter_storage(_parameter_view(variable), variable.name) == [storage]
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[variable])
    [report] = _run_uses(_uses_view([call], {variable: [call]}))["variables"]
    assert report["storage"] == storage


def test_parameter_storage_lists_every_same_named_variable_in_function_order() -> None:
    first = _stack_variable("category", 8)
    second = FakeVariable("category", storage=105)
    third = _stack_variable("category", -16)
    other = FakeVariable("other", storage=104)
    view = _parameter_view(first, other, second, third)
    assert _parameter_storage(view, "category") == [
        {"source": "stack", "stack_offset": 8},
        {"source": "register", "register": "rdi"},
        {"source": "stack", "stack_offset": -16},
    ]
    assert _parameter_storage(view, "other") == [{"source": "register", "register": "rsi"}]


def test_parameter_storage_resolves_registers_through_the_function_architecture() -> None:
    variable = FakeVariable("v", storage=98)
    view = _parameter_view(variable, arch=FakeArchitecture("arm64", {98: "x0"}, {}))
    assert _parameter_storage(view, "v") == [{"source": "register", "register": "x0"}]


def test_parameter_rejects_a_variable_source_type_the_plugin_does_not_know() -> None:
    variable = FakeVariable("v")
    variable.source_type = 99  # ty: ignore[invalid-assignment]
    with pytest.raises(ValueError, match=r"^unknown variable source type 99$"):
        _parameter_storage(_parameter_view(variable), "v")


def test_parameter_carriers_scan_every_use_and_sort_by_address() -> None:
    # The scan must move past uses that are not copies, and the report sorts carriers by
    # address whatever order the core lists the uses in.
    arg4 = FakeVariable("arg4")
    r14 = FakeVariable("r14")
    r15 = FakeVariable("r15")
    entry = FakeSSAVariable(arg4, 0)
    ssa = FakeMLILSSA(
        [
            set_var_ssa(
                0x1010, FakeSSAVariable(FakeVariable("tmp"), 1), load(var_ssa(entry)), "tmp"
            ),
            branch(0x1020, var_ssa(entry)),
            set_var_ssa(0x1400, FakeSSAVariable(r14, 1), var_ssa(entry), "r14 = arg4"),
            set_var_ssa(0x1040, FakeSSAVariable(r15, 1), var_ssa(entry), "r15 = arg4"),
        ]
    )
    mlil = FakeMLILInstructions(instructions=[], ssa_form=ssa)
    function = FakeFunction("check", 0x1000, 0x1100, mlil=mlil, vars=[arg4, r14, r15])
    view = FakeBinaryView(functions=[function])
    _, parameter = get_tool("rex_parameter_variables")
    result = parameter(_call(view), function=0x1000, parameter="arg4")
    assert result["carriers"] == [
        {"variable": "r15", "address": "0x1040", "text": "r15 = arg4"},
        {"variable": "r14", "address": "0x1400", "text": "r14 = arg4"},
    ]


# (operation, operator with the subject on the left, operator mirrored, signed)
_ORDERED = [
    ("MLIL_CMP_SLT", "s<", "s>", True),
    ("MLIL_CMP_ULT", "u<", "u>", False),
    ("MLIL_CMP_SLE", "s<=", "s>=", True),
    ("MLIL_CMP_ULE", "u<=", "u>=", False),
    ("MLIL_CMP_SGE", "s>=", "s<=", True),
    ("MLIL_CMP_UGE", "u>=", "u<=", False),
    ("MLIL_CMP_SGT", "s>", "s<", True),
    ("MLIL_CMP_UGT", "u>", "u<", False),
]


def _range_rows(*conditions: FakeInstruction, **arguments: Any) -> list[dict[str, Any]]:
    branches = [
        branch(0x6010 + 0x10 * position, condition) for position, condition in enumerate(conditions)
    ]
    function = FakeFunction("range", 0x6000, 0x6100, mlil=FakeMLILInstructions(branches))
    _, constraints = get_tool("rex_function_constraints")
    result = constraints(_call(FakeBinaryView(functions=[function])), function=0x6000, **arguments)
    return result["constraints"]


def _range_row(operator: str, constant: str, signed: str | None) -> dict[str, Any]:
    row: dict[str, Any] = {
        "address": "0x6010",
        "operator": operator,
        "constant": constant,
        "char": None,
        "subject": {"kind": "variable", "variable": "value"},
        "subject_text": "value",
    }
    if signed is not None:
        row["signed_constant"] = signed
    return row


@pytest.mark.parametrize(("operation", "operator", "mirrored", "signed"), _ORDERED)
def test_all_reports_an_ordered_comparison_with_the_subject_on_the_left(
    operation: str, operator: str, mirrored: str, signed: bool
) -> None:
    del mirrored
    condition = compare(operation, var(FakeVariable("value")), const(9))
    assert _range_rows(condition, operators="all") == [
        _range_row(operator, "0x9", "0x9" if signed else None)
    ]


@pytest.mark.parametrize(("operation", "operator", "mirrored", "signed"), _ORDERED)
def test_all_mirrors_an_ordered_comparison_with_the_constant_on_the_left(
    operation: str, operator: str, mirrored: str, signed: bool
) -> None:
    del operator
    condition = compare(operation, const(9), var(FakeVariable("value")))
    assert _range_rows(condition, operators="all") == [
        _range_row(mirrored, "0x9", "0x9" if signed else None)
    ]


@pytest.mark.parametrize("operation", [entry[0] for entry in _ORDERED])
@pytest.mark.parametrize("arguments", [{}, {"operators": "equality"}])
def test_equality_mode_omits_ordered_comparisons(operation: str, arguments: dict[str, Any]) -> None:
    value = FakeVariable("value")
    conditions = (
        compare(operation, var(value), const(9)),
        compare("MLIL_CMP_E", var(value), const(0x41)),
    )
    assert _range_rows(*conditions, **arguments) == [
        {
            "address": "0x6020",
            "operator": "==",
            "constant": "0x41",
            "char": "A",
            "subject": {"kind": "variable", "variable": "value"},
            "subject_text": "value",
        }
    ]


def test_all_keeps_equality_rows_exactly_as_equality_mode_reports_them() -> None:
    value = FakeVariable("value")
    conditions = (
        compare("MLIL_CMP_NE", const(-1, size=4), var(value)),
        compare("MLIL_CMP_SLT", var(value), const(0x40)),
        compare("MLIL_CMP_E", var(value), const(0x41)),
    )
    everything = _range_rows(*conditions, operators="all")
    assert [row["operator"] for row in everything] == ["!=", "s<", "=="]
    assert [everything[0], everything[2]] == _range_rows(*conditions)


@pytest.mark.parametrize(
    ("condition", "operator", "constant", "signed"),
    [
        (
            compare("MLIL_CMP_SLT", var(FakeVariable("value")), const(-1, size=4)),
            "s<",
            "0xffffffff",
            "-0x1",
        ),
        (
            compare("MLIL_CMP_SLT", const(-1, size=4), var(FakeVariable("value"))),
            "s>",
            "0xffffffff",
            "-0x1",
        ),
        (
            compare("MLIL_CMP_SGE", var(FakeVariable("value")), const(-0x80, size=1)),
            "s>=",
            "0x80",
            "-0x80",
        ),
        (
            compare("MLIL_CMP_SLE", var(FakeVariable("value")), const(0x7F, size=1)),
            "s<=",
            "0x7f",
            "0x7f",
        ),
        (
            compare(
                "MLIL_CMP_SGT",
                var(FakeVariable("value")),
                sign_extend(const(-1, size=4), value=constant_value(-1)),
            ),
            "s>",
            "0xffffffffffffffff",
            "-0x1",
        ),
        (compare("MLIL_CMP_SGT", var(FakeVariable("value")), const(1, size=0)), "s>", "0x1", "0x1"),
        (
            compare("MLIL_CMP_ULT", var(FakeVariable("value")), const(-1, size=4)),
            "u<",
            "0xffffffff",
            None,
        ),
        (
            compare("MLIL_CMP_UGE", const(-1, size=4), var(FakeVariable("value"))),
            "u<=",
            "0xffffffff",
            None,
        ),
    ],
)
def test_signed_comparisons_add_the_signed_reading_of_the_constant(
    condition: FakeInstruction, operator: str, constant: str, signed: str | None
) -> None:
    assert _range_rows(condition, operators="all") == [_range_row(operator, constant, signed)]


@pytest.mark.parametrize(
    ("extended", "constant", "signed"),
    [
        (
            zero_extend(const(0x80000000, size=4), value=constant_value(0x80000000)),
            "0x80000000",
            "0x80000000",
        ),
        (
            sign_extend(const(0x80000000, size=4), value=constant_value(-0x80000000)),
            "0xffffffff80000000",
            "-0x80000000",
        ),
    ],
)
def test_a_signed_reading_uses_the_width_after_extension(
    extended: FakeInstruction, constant: str, signed: str
) -> None:
    condition = compare("MLIL_CMP_SLT", var(FakeVariable("value")), extended)
    assert _range_rows(condition, operators="all") == [_range_row("s<", constant, signed)]


def test_all_skips_ordered_comparisons_without_exactly_one_constant() -> None:
    value, other = FakeVariable("value"), FakeVariable("other")
    conditions = (
        compare("MLIL_CMP_ULT", const(1), const(2)),
        compare("MLIL_CMP_SGT", var(value), var(other)),
    )
    assert _range_rows(*conditions, operators="all") == []


@pytest.mark.parametrize(
    ("operators", "shown"),
    [
        ("ordered", "ordered"),
        ("", ""),
        ("a\x00ll", "a\N{REPLACEMENT CHARACTER}ll"),
        ("x" * 513, "x" * 512 + "... [1 chars truncated]"),
    ],
)
def test_constraints_reject_an_unknown_operator_set(operators: str, shown: str) -> None:
    with pytest.raises(FakeToolError) as error:
        _range_rows(operators=operators)
    assert error.value.code == "invalid_params"
    assert error.value.message == f"operators must be 'equality' or 'all', not '{shown}'"


def test_constraints_schema_offers_the_operator_sets_with_equality_by_default() -> None:
    options, function = get_tool("rex_function_constraints")
    schema = FakeTool("rex_function_constraints", options, function).input_schema
    assert schema["required"] == ["function"]
    assert schema["properties"]["operators"] == {
        "type": "string",
        "enum": ["equality", "all"],
        "default": "equality",
        "description": "Comparisons to report: equality (== and !=) or all (adds s<, u>=, ...).",
    }
