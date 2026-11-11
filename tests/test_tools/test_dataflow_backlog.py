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
    var,
)
from helpers_uidf import FakeMediumLevelIL, FakeVariable
from helpers_view import FakeBinaryView, FakeFunction

_TIP = (
    "Register-allocated parameters are named by their register (for example r14), "
    "not by their argument name"
)


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


def _unknown_name_message(tool_name: str, function: FakeFunction, *arguments: Any) -> str:
    _, tool = get_tool(tool_name)
    view = FakeBinaryView(functions=[function])
    with pytest.raises(FakeToolError) as error:
        tool(_call(view), *arguments)
    assert error.value.code == "no_variable"
    return error.value.message


def _parameter_function(parameter_names: list[str]) -> FakeFunction:
    variables = [FakeVariable("r14"), FakeVariable("var_10")]
    return FakeFunction(
        "check",
        0x1000,
        0x1100,
        vars=variables,
        parameter_vars=[FakeVariable(name) for name in parameter_names],
        mlil=FakeMediumLevelIL({variables[0]: [0x1004]}),
    )


def test_unknown_variable_that_is_not_a_parameter_gets_no_register_tip() -> None:
    function = _parameter_function(["arg1"])
    expected = (
        "no MLIL variable named 'nope' in check; variables: r14, var_10; "
        "use bn_variable_list for the full list"
    )
    assert _unknown_name_message("rex_uidf_set", function, 0x1004, "nope", "1") == expected
    assert _unknown_name_message("rex_parameter_variables", function, 0x1000, "nope") == expected


def test_unknown_variable_that_is_a_declared_parameter_gets_the_register_tip() -> None:
    function = _parameter_function(["arg1", "arg2"])
    expected = (
        "no MLIL variable named 'arg2' in check; variables: r14, var_10; "
        f"use bn_variable_list for the full list. {_TIP}"
    )
    assert _unknown_name_message("rex_uidf_set", function, 0x1004, "arg2", "1") == expected
    assert _unknown_name_message("rex_parameter_variables", function, 0x1000, "arg2") == expected


def test_function_without_parameters_gives_no_register_tip() -> None:
    message = _unknown_name_message("rex_uidf_clear", _parameter_function([]), 0x1004, "arg1")
    assert _TIP not in message


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
