from __future__ import annotations

from typing import Any

import pytest
from helpers import FakeToolError, _call, get_tool
from helpers_dataflow import (
    FakeMLILInstructions,
    add,
    branch,
    compare,
    const,
    load,
    set_var,
    sign_extend,
    var,
    zero_extend,
)
from helpers_uidf import FakeMediumLevelIL, FakeVariable, FakeVariableSourceType
from helpers_view import FakeBinaryView, FakeFunction


def _constants(*constants: Any) -> list[dict[str, Any]]:
    subject = FakeVariable("value")
    instructions = [
        branch(0x1000 + 0x10 * position, compare("MLIL_CMP_E", var(subject), constant))
        for position, constant in enumerate(constants)
    ]
    function = FakeFunction("check", 0x1000, 0x1100, mlil=FakeMLILInstructions(instructions))
    _, constraints = get_tool("rex_function_constraints")
    return constraints(_call(FakeBinaryView(functions=[function])), function=0x1000)["constraints"]


@pytest.mark.parametrize(
    ("constant", "expected"),
    [
        (const(-1, size=8), "0xffffffffffffffff"),
        (const(0xFFFFFFFF, size=8), "0xffffffff"),
        (const(0xFFFFFFFF, size=4), "0xffffffff"),
        (const(-1, size=4), "0xffffffff"),
        (const(-1, size=2), "0xffff"),
        (const(-1, size=1), "0xff"),
        (const(-0x80, size=1), "0x80"),
        (const(0x70, size=1), "0x70"),
        (const(0, size=8), "0x0"),
    ],
)
def test_constraint_constant_is_unsigned_at_its_own_width(constant: Any, expected: str) -> None:
    assert _constants(constant)[0]["constant"] == expected


def test_minus_one_reads_the_same_in_both_core_forms_on_either_side() -> None:
    rows = _constants(const(0xFFFFFFFF, size=4), const(-1, size=4))
    assert [row["constant"] for row in rows] == ["0xffffffff", "0xffffffff"]
    subject = FakeVariable("value")
    left = branch(0x2000, compare("MLIL_CMP_NE", const(-1, size=8), var(subject)))
    function = FakeFunction("left", 0x2000, 0x2100, mlil=FakeMLILInstructions([left]))
    _, constraints = get_tool("rex_function_constraints")
    row = constraints(_call(FakeBinaryView(functions=[function])), function=0x2000)["constraints"][
        0
    ]
    assert row["constant"] == "0xffffffffffffffff"
    assert row["char"] is None


def test_negative_load_displacement_stays_signed() -> None:
    base = FakeVariable("rbp_1")
    address = add(var(base), const(-0xF8))
    condition = compare("MLIL_CMP_E", load(address), const(-1, size=8))
    function = FakeFunction(
        "frame", 0x3000, 0x3100, mlil=FakeMLILInstructions([branch(0x3010, condition)])
    )
    _, constraints = get_tool("rex_function_constraints")
    row = constraints(_call(FakeBinaryView(functions=[function])), function=0x3000)["constraints"][
        0
    ]
    assert row["subject"] == {"kind": "load", "base": "rbp_1", "offset": "-0xf8"}
    assert row["constant"] == "0xffffffffffffffff"


def _error_message(tool_name: str, function: FakeFunction, *arguments: Any) -> tuple[str, str]:
    _, tool = get_tool(tool_name)
    view = FakeBinaryView(functions=[function])
    with pytest.raises(FakeToolError) as error:
        tool(_call(view), *arguments)
    return error.value.code, error.value.message


def _function_with(variables: list[FakeVariable]) -> FakeFunction:
    return FakeFunction(
        "check",
        0x1000,
        0x1100,
        vars=variables,
        mlil=FakeMediumLevelIL({variables[0]: [0x1004]}),
    )


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("rex_uidf_set", (0x1004, "arg1", "1")),
        ("rex_uidf_clear", (0x1004, "arg1")),
        ("rex_parameter_variables", (0x1000, "arg1")),
    ],
)
def test_unknown_variable_message_gives_no_register_advice(
    tool_name: str, arguments: tuple[Any, ...]
) -> None:
    function = _function_with([FakeVariable("r14"), FakeVariable("var_10")])
    assert _error_message(tool_name, function, *arguments) == (
        "no_variable",
        "no MLIL variable named 'arg1' in check; variables: r14, var_10; "
        "use bn_variable_list for the full list",
    )


_REGISTER_ADVICE = (
    "; a register parameter is live from function entry, inform a variable that "
    "copies it (rex_parameter_variables lists the copies)"
)
_STACK_ADVICE = (
    "; stack-passed arguments cannot be informed, inform the register that loads the value"
)


def _argument(source_type: FakeVariableSourceType) -> FakeVariable:
    return FakeVariable("arg", source_type=source_type)


@pytest.mark.parametrize(
    ("variables", "advice"),
    [
        ([_argument(FakeVariableSourceType.RegisterVariableSourceType)], _REGISTER_ADVICE),
        ([_argument(FakeVariableSourceType.StackVariableSourceType)], _STACK_ADVICE),
        ([_argument(FakeVariableSourceType.FlagVariableSourceType)], ""),
        (
            [
                _argument(FakeVariableSourceType.StackVariableSourceType),
                _argument(FakeVariableSourceType.RegisterVariableSourceType),
            ],
            "",
        ),
    ],
)
def test_variable_without_definitions_gets_advice_matching_its_source_type(
    variables: list[FakeVariable], advice: str
) -> None:
    function = FakeFunction("check", 0x1000, 0x1100, vars=variables, mlil=FakeMediumLevelIL({}))
    for tool_name, arguments in (
        ("rex_uidf_set", (0x1004, "arg", "1")),
        ("rex_uidf_clear", (0x1004, "arg")),
    ):
        assert _error_message(tool_name, function, *arguments) == (
            "no_variable",
            "MLIL variable 'arg' in check has no MediumLevelIL definition sites" + advice,
        )


def _constraint_row(condition: Any) -> dict[str, Any]:
    function = FakeFunction(
        "shape", 0x4000, 0x4100, mlil=FakeMLILInstructions([branch(0x4010, condition)])
    )
    _, constraints = get_tool("rex_function_constraints")
    return constraints(_call(FakeBinaryView(functions=[function])), function=0x4000)["constraints"][
        0
    ]


@pytest.mark.parametrize(
    ("wrapped", "expected"),
    [
        (zero_extend(const(0xFFFFFFFF, size=4)), "0xffffffff"),
        (zero_extend(const(-1, size=4)), "0xffffffff"),
        (sign_extend(const(-1, size=4)), "0xffffffff"),
        (sign_extend(const(-1, size=1), size=4), "0xff"),
        (zero_extend(sign_extend(const(-1, size=2), size=4)), "0xffff"),
    ],
)
def test_constraint_constant_width_is_the_constant_operands_inside_extensions(
    wrapped: Any, expected: str
) -> None:
    row = _constraint_row(compare("MLIL_CMP_E", var(FakeVariable("value")), wrapped))
    assert row["constant"] == expected


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        (const(0xFFFF0000, size=4), "0xffff0000"),
        (const(-0x1000, size=8), "0xfffffffffffff000"),
        (const(0x403198, size=8), "0x403198"),
        (zero_extend(const(-0x1000, size=4)), "0xfffff000"),
    ],
)
def test_absolute_load_address_is_unsigned_at_its_width(address: Any, expected: str) -> None:
    row = _constraint_row(compare("MLIL_CMP_E", load(address), const(1)))
    assert row["subject"] == {"kind": "load", "base": None, "offset": expected}


@pytest.mark.parametrize(
    ("displacement", "expected"),
    [
        (const(-8, size=8), "-0x8"),
        (const(0xFFFFFFFFFFFFFFF8, size=8), "-0x8"),
        (const(0xFFFFFFF8, size=4), "-0x8"),
        (const(-8, size=4), "-0x8"),
        (const(0xF8, size=1), "-0x8"),
        (const(0x7FFFFFFF, size=4), "0x7fffffff"),
        (const(0x80000000, size=4), "-0x80000000"),
        (const(0x7F, size=1), "0x7f"),
        (const(0, size=4), "0x0"),
        (zero_extend(const(0xFFFFFFF8, size=4)), "-0x8"),
    ],
)
def test_load_displacement_is_signed_two_complement_at_its_width(
    displacement: Any, expected: str
) -> None:
    address = add(var(FakeVariable("rbp_1")), displacement)
    row = _constraint_row(compare("MLIL_CMP_E", load(address), const(1)))
    assert row["subject"] == {"kind": "load", "base": "rbp_1", "offset": expected}


def _redefined_view() -> FakeBinaryView:
    value = FakeVariable("value")
    late = set_var(0x1030, value, const(3))
    early = set_var(0x1010, value, const(1))
    middle = set_var(0x1020, value, const(2))
    mlil = FakeMLILInstructions(
        [early, middle, late], definitions={value: [late, early, middle]}, uses={value: []}
    )
    return FakeBinaryView(functions=[FakeFunction("check", 0x1000, 0x1100, mlil=mlil)])


def test_mlil_uses_definitions_are_sorted_by_address() -> None:
    _, uses = get_tool("rex_mlil_uses")
    report = uses(_call(_redefined_view()), function=0x1000, address=0x1020)["variables"][0]
    assert report["definitions"] == ["0x1010", "0x1020", "0x1030"]


def test_mlil_uses_definitions_sort_by_number_not_by_text() -> None:
    value = FakeVariable("value")
    wide = set_var(0x10000, value, const(1))
    narrow = set_var(0x2000, value, const(2))
    mlil = FakeMLILInstructions(
        [narrow, wide], definitions={value: [wide, narrow]}, uses={value: []}
    )
    view = FakeBinaryView(functions=[FakeFunction("check", 0x1000, 0x1100, mlil=mlil)])
    _, uses = get_tool("rex_mlil_uses")
    report = uses(_call(view), function=0x1000, address=0x2000)["variables"][0]
    assert report["definitions"] == ["0x2000", "0x10000"]


def _parameter_definitions(first: list[int], second: list[int]) -> list[str]:
    first_variable, second_variable = FakeVariable("arg4"), FakeVariable("arg4")
    mlil = FakeMLILInstructions(
        [],
        definitions={
            first_variable: [set_var(address, first_variable, const(1)) for address in first],
            second_variable: [set_var(address, second_variable, const(1)) for address in second],
        },
    )
    function = FakeFunction(
        "check", 0x1000, 0x20000, vars=[first_variable, second_variable], mlil=mlil
    )
    _, parameter = get_tool("rex_parameter_variables")
    result = parameter(
        _call(FakeBinaryView(functions=[function])), function=0x1000, parameter="arg4"
    )
    return list(result["definitions"])


def test_parameter_definitions_are_sorted_by_address_across_matching_variables() -> None:
    assert _parameter_definitions([0x1030, 0x1010], [0x1020]) == ["0x1010", "0x1020", "0x1030"]


def test_parameter_definitions_sort_by_number_not_by_text() -> None:
    assert _parameter_definitions([0x10000], [0x2000]) == ["0x2000", "0x10000"]


def test_load_with_a_variable_displacement_states_no_offset() -> None:
    address = add(var(FakeVariable("base")), var(FakeVariable("index")))
    row = _constraint_row(compare("MLIL_CMP_E", load(address), const(1)))
    assert row["subject"] == {
        "kind": "load",
        "base": None,
        "offset": None,
        "text": "base + index",
    }
