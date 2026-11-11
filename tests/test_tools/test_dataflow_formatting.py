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


_REGISTER = FakeVariableSourceType.RegisterVariableSourceType
_STACK = FakeVariableSourceType.StackVariableSourceType
_FLAG = FakeVariableSourceType.FlagVariableSourceType


def _variable_named(name: str, source_type: FakeVariableSourceType) -> FakeVariable:
    return FakeVariable(name, source_type=source_type)


def _no_definition_message(name: str) -> str:
    return f"MLIL variable '{name}' in check has no MediumLevelIL definition sites"


def _assert_advice(
    variables: list[FakeVariable], parameters: list[FakeVariable], name: str, advice: str
) -> None:
    function = FakeFunction(
        "check",
        0x1000,
        0x1100,
        vars=variables,
        parameter_vars=parameters,
        mlil=FakeMediumLevelIL({}),
    )
    for tool_name, arguments in (
        ("rex_uidf_set", (0x1004, name, "1")),
        ("rex_uidf_clear", (0x1004, name)),
    ):
        assert _error_message(tool_name, function, *arguments) == (
            "no_variable",
            _no_definition_message(name) + advice,
        )


def test_register_parameter_without_definitions_gets_the_register_advice() -> None:
    argc = _variable_named("argc", _REGISTER)
    _assert_advice([argc], [argc], "argc", _REGISTER_ADVICE)


def test_stack_parameter_without_definitions_gets_the_stack_advice() -> None:
    argument = _variable_named("arg8", _STACK)
    _assert_advice([argument], [argument], "arg8", _STACK_ADVICE)


@pytest.mark.parametrize(
    ("name", "source_type"),
    [("rbx", _REGISTER), ("fsbase", _REGISTER), ("category", _STACK), ("cond0", _FLAG)],
)
def test_non_parameter_without_definitions_gets_no_advice(
    name: str, source_type: FakeVariableSourceType
) -> None:
    local = _variable_named(name, source_type)
    other_parameter = _variable_named("argc", _REGISTER)
    _assert_advice([local, other_parameter], [other_parameter], name, "")


def test_parameter_of_another_source_type_gets_no_advice() -> None:
    flag = _variable_named("flag", _FLAG)
    _assert_advice([flag], [flag], "flag", "")


def test_parameter_membership_compares_variables_by_value_not_identity() -> None:
    listed = FakeVariable("argc", index=7)
    parameter = FakeVariable("argc", index=7)
    assert listed is not parameter
    _assert_advice([listed], [parameter], "argc", _REGISTER_ADVICE)


def test_a_variable_differing_in_index_is_not_the_listed_parameter() -> None:
    local = FakeVariable("argc", index=7)
    other_parameter = FakeVariable("argc", index=8)
    _assert_advice([local], [other_parameter], "argc", "")


def test_fake_variables_compare_and_hash_by_source_type_index_and_storage() -> None:
    original = FakeVariable("a", index=3, storage=5)
    assert original == FakeVariable("renamed", index=3, storage=5, type_string="char")
    assert hash(original) == hash(FakeVariable("renamed", index=3, storage=5))
    assert original != FakeVariable("a", index=4, storage=5)
    assert original != FakeVariable("a", index=3, storage=6)
    assert original != FakeVariable("a", index=3, storage=5, source_type=_STACK)
    assert original != "a"
    assert len({original, FakeVariable("a", index=3, storage=5)}) == 1


def test_fake_variables_are_distinct_unless_given_the_same_index() -> None:
    assert FakeVariable("v") != FakeVariable("v")


def test_same_named_parameter_and_local_get_no_advice() -> None:
    parameter, local = _variable_named("v", _REGISTER), _variable_named("v", _REGISTER)
    _assert_advice([parameter, local], [parameter], "v", "")


def test_same_named_parameters_of_different_source_types_get_no_advice() -> None:
    register, stack = _variable_named("v", _REGISTER), _variable_named("v", _STACK)
    _assert_advice([register, stack], [register, stack], "v", "")


def test_variable_names_match_exactly_not_by_prefix_or_substring() -> None:
    prefixed = _variable_named("arg1", _STACK)
    suffixed = _variable_named("xarg", _STACK)
    wrapped = _variable_named("xargx", _STACK)
    function = FakeFunction(
        "check",
        0x1000,
        0x1100,
        vars=[prefixed, suffixed, wrapped],
        parameter_vars=[prefixed, suffixed, wrapped],
        mlil=FakeMediumLevelIL({}),
    )
    for tool_name, arguments in (
        ("rex_uidf_set", (0x1004, "arg", "1")),
        ("rex_uidf_clear", (0x1004, "arg")),
    ):
        code, message = _error_message(tool_name, function, *arguments)
        assert code == "no_variable"
        assert message.startswith("no MLIL variable named 'arg' in check; variables: ")


def test_exact_name_advice_ignores_longer_same_prefix_variables() -> None:
    exact = _variable_named("arg", _REGISTER)
    longer = _variable_named("arg1", _STACK)
    _assert_advice([exact, longer], [exact, longer], "arg", _REGISTER_ADVICE)


def _constraint_row(condition: Any) -> dict[str, Any]:
    function = FakeFunction(
        "shape", 0x4000, 0x4100, mlil=FakeMLILInstructions([branch(0x4010, condition)])
    )
    _, constraints = get_tool("rex_function_constraints")
    return constraints(_call(FakeBinaryView(functions=[function])), function=0x4000)["constraints"][
        0
    ]


@pytest.mark.parametrize(
    ("wrapped", "expected", "character"),
    [
        (const(1, size=0), "0x1", None),
        (const(0, size=0), "0x0", None),
        (zero_extend(const(1, size=0)), "0x1", None),
        (sign_extend(const(-1, size=0), size=0), "-0x1", None),
        (zero_extend(const(0xFFFFFFFF, size=4)), "0xffffffff", None),
        (zero_extend(const(-1, size=4)), "0xffffffff", None),
        (sign_extend(const(-1, size=4)), "0xffffffffffffffff", None),
        (sign_extend(const(0xFFFFFFFF, size=4)), "0xffffffffffffffff", None),
        (sign_extend(const(-1, size=1), size=4), "0xffffffff", None),
        (sign_extend(const(0x80, size=1), size=4), "0xffffff80", None),
        (sign_extend(const(0x7F, size=1), size=4), "0x7f", None),
        (zero_extend(const(-1, size=1), size=4), "0xff", None),
        (zero_extend(sign_extend(const(-1, size=2), size=4)), "0xffffffff", None),
        (sign_extend(zero_extend(const(-1, size=2), size=4)), "0xffff", None),
        (sign_extend(const(0x41, size=1)), "0x41", "A"),
        (zero_extend(const(0x41, size=1), size=4), "0x41", "A"),
        (zero_extend(const(0x41, size=4), size=0), "0x41", "A"),
    ],
)
def test_constraint_constant_is_the_value_the_expression_computes(
    wrapped: Any, expected: str, character: str | None
) -> None:
    row = _constraint_row(compare("MLIL_CMP_E", var(FakeVariable("value")), wrapped))
    assert row["constant"] == expected
    assert row["char"] == character


def test_extended_constant_on_the_left_renders_the_computed_value() -> None:
    row = _constraint_row(
        compare("MLIL_CMP_NE", sign_extend(const(-1, size=4)), var(FakeVariable("value")))
    )
    assert row["constant"] == "0xffffffffffffffff"
    assert row["char"] is None


def test_extension_of_a_non_constant_states_no_constraint() -> None:
    condition = compare(
        "MLIL_CMP_E", var(FakeVariable("value")), zero_extend(var(FakeVariable("other")))
    )
    function = FakeFunction(
        "none", 0x5000, 0x5100, mlil=FakeMLILInstructions([branch(0x5010, condition)])
    )
    _, constraints = get_tool("rex_function_constraints")
    result = constraints(_call(FakeBinaryView(functions=[function])), function=0x5000)
    assert result["constraints"] == []


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        (const(0xFFFF0000, size=4), "0xffff0000"),
        (const(-0x1000, size=8), "0xfffffffffffff000"),
        (const(0x403198, size=8), "0x403198"),
        (zero_extend(const(-0x1000, size=4)), "0xfffff000"),
        (sign_extend(const(-0x1000, size=4)), "0xfffffffffffff000"),
        (sign_extend(const(0xFFFFF000, size=4)), "0xfffffffffffff000"),
        (sign_extend(const(0x1000, size=4)), "0x1000"),
        (sign_extend(const(0x7FFFFFFF, size=4)), "0x7fffffff"),
        (sign_extend(const(0x80000000, size=4)), "0xffffffff80000000"),
        (zero_extend(sign_extend(const(-1, size=1), size=2), size=8), "0xffff"),
        (sign_extend(sign_extend(const(-1, size=1), size=2), size=8), "0xffffffffffffffff"),
        (const(0x10, size=0), "0x10"),
        (sign_extend(const(1, size=0)), "0x1"),
        (zero_extend(const(1, size=4), size=0), "0x1"),
    ],
)
def test_absolute_load_address_is_the_unsigned_value_the_expression_computes(
    address: Any, expected: str
) -> None:
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
        (zero_extend(const(0xFFFFFFF8, size=4)), "0xfffffff8"),
        (zero_extend(const(-8, size=4)), "0xfffffff8"),
        (sign_extend(const(0xFFFFFFF8, size=4)), "-0x8"),
        (sign_extend(const(-8, size=4)), "-0x8"),
        (sign_extend(const(8, size=4)), "0x8"),
        (zero_extend(sign_extend(const(-8, size=4), size=8), size=8), "-0x8"),
        (zero_extend(sign_extend(const(-8, size=1), size=4), size=8), "0xfffffff8"),
        (const(5, size=0), "0x5"),
        (const(-5, size=0), "-0x5"),
        (zero_extend(const(5, size=0)), "0x5"),
        (zero_extend(const(5, size=4), size=0), "0x5"),
        (sign_extend(const(-5, size=4), size=0), "-0x5"),
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


def test_extended_variable_address_is_a_base_with_a_zero_offset() -> None:
    address = zero_extend(var(FakeVariable("pointer")))
    row = _constraint_row(compare("MLIL_CMP_E", load(address), const(1)))
    assert row["subject"] == {"kind": "load", "base": "pointer", "offset": "0x0"}
