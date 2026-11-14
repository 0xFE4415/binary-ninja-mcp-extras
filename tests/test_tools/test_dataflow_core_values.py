from __future__ import annotations

from typing import Any

import pytest
from helpers import FakeToolError, _call, get_tool
from helpers_dataflow import (
    FakeInstruction,
    FakeMediumLevelILOperation,
    FakeMLILInstructions,
    FakeMLILSSA,
    FakeSSAVariable,
    add,
    branch,
    compare,
    const,
    const_pointer,
    constant_value,
    float_const,
    import_address,
    load,
    load_struct,
    low_part,
    phi,
    set_var,
    set_var_ssa,
    sign_extend,
    var,
    var_ssa,
    zero_extend,
)
from helpers_uidf import FakeVariable
from helpers_view import FakeBinaryView, FakeFunction


def _rows(
    *conditions: FakeInstruction,
    definitions: dict[FakeVariable, list[FakeInstruction]] | None = None,
    operators: str = "equality",
) -> list[dict[str, Any]]:
    branches = [
        branch(0x7010 + 0x10 * position, condition) for position, condition in enumerate(conditions)
    ]
    mlil = FakeMLILInstructions(branches, definitions=definitions)
    function = FakeFunction("values", 0x7000, 0x7100, mlil=mlil)
    _, constraints = get_tool("rex_function_constraints")
    result = constraints(
        _call(FakeBinaryView(functions=[function])), function=0x7000, operators=operators
    )
    return result["constraints"]


def _known(name: str, value: int, size: int = 8) -> FakeInstruction:
    known = var(FakeVariable(name))
    known.value = constant_value(value)
    known.size = size
    return known


def test_a_variable_the_core_states_constant_is_the_compared_constant() -> None:
    rows = _rows(compare("MLIL_CMP_E", var(FakeVariable("input")), _known("key", -2, size=4)))
    assert rows == [
        {
            "address": "0x7010",
            "operator": "==",
            "constant": "0xfffffffe",
            "char": None,
            "subject": {"kind": "variable", "variable": "input"},
            "subject_text": "input",
        }
    ]


def test_a_constant_pointer_value_is_a_constant() -> None:
    rows = _rows(compare("MLIL_CMP_NE", var(FakeVariable("cursor")), const_pointer(0x403010)))
    assert rows[0]["constant"] == "0x403010"


def test_an_extension_the_core_states_no_value_for_is_no_constant() -> None:
    assert _rows(compare("MLIL_CMP_E", var(FakeVariable("value")), sign_extend(const(-1, 4)))) == []


def test_an_extension_reads_the_value_the_core_states_at_its_own_width() -> None:
    folded = sign_extend(const(0xFFFFFFFF, 4), value=constant_value(-1))
    rows = _rows(compare("MLIL_CMP_SLT", var(FakeVariable("value")), folded), operators="all")
    assert (rows[0]["constant"], rows[0]["signed_constant"]) == ("0xffffffffffffffff", "-0x1")


def test_an_import_is_described_as_its_address_slot_and_never_folded_to_a_constant() -> None:
    gmon = import_address(0x402FE0, "__gmon_start__")
    rows = _rows(
        compare("MLIL_CMP_E", gmon, const(0)),
        compare("MLIL_CMP_E", var(FakeVariable("pointer")), import_address(0x402FE8, "puts")),
    )
    assert rows == [
        {
            "address": "0x7010",
            "operator": "==",
            "constant": "0x0",
            "char": None,
            "subject": {"kind": "import", "address": "0x402fe0", "text": "__gmon_start__"},
            "subject_text": "__gmon_start__",
        }
    ]


@pytest.mark.parametrize(
    ("address", "offset", "subject"),
    [
        (var(FakeVariable("rax")), 8, {"kind": "load", "base": "rax", "offset": "0x8"}),
        (
            add(var(FakeVariable("rbp")), const(-0x10)),
            0xC,
            {"kind": "load", "base": "rbp", "offset": "-0x4"},
        ),
        (
            zero_extend(var(FakeVariable("pointer"))),
            0,
            {"kind": "load", "base": "pointer", "offset": "0x0"},
        ),
        (const_pointer(0x403000), 0x10, {"kind": "load", "base": None, "offset": "0x403010"}),
        (
            load(var(FakeVariable("table"))),
            4,
            {"kind": "load", "base": None, "offset": None, "text": "*(table)"},
        ),
    ],
)
def test_a_struct_field_load_reads_its_base_and_field_offset(
    address: FakeInstruction, offset: int, subject: dict[str, object]
) -> None:
    rows = _rows(compare("MLIL_CMP_NE", load_struct(address, offset, "field"), const(0x1234, 4)))
    assert rows[0]["subject"] == subject


def test_a_variable_defined_by_a_struct_field_load_names_that_load() -> None:
    field = FakeVariable("rax_1")
    definition = set_var(0x7004, field, load_struct(var(FakeVariable("rax")), 8, "b"))
    rows = _rows(
        compare("MLIL_CMP_NE", var(field), const(0x1234, 4)), definitions={field: [definition]}
    )
    assert rows[0]["subject"] == {
        "kind": "variable",
        "variable": "rax_1",
        "definition": {
            "address": "0x7004",
            "load": {"kind": "load", "base": "rax", "offset": "0x8"},
        },
    }


def test_a_low_part_reads_through_to_the_variable_or_load_it_narrows() -> None:
    rows = _rows(
        compare("MLIL_CMP_E", low_part(var(FakeVariable("wide"))), const(0x41, 1)),
        compare("MLIL_CMP_E", low_part(load(var(FakeVariable("text")))), const(0x42, 1)),
    )
    assert [row["subject"] for row in rows] == [
        {"kind": "variable", "variable": "wide"},
        {"kind": "load", "base": "text", "offset": "0x0"},
    ]


_DOUBLE_3_5 = 0x400C000000000000
_SINGLE_1_5 = 0x3FC00000


def test_float_equality_reports_the_bits_and_the_number() -> None:
    rows = _rows(
        compare("MLIL_FCMP_NE", var(FakeVariable("zmm0")), float_const(3.5, _DOUBLE_3_5)),
        compare("MLIL_FCMP_E", float_const(1.5, _SINGLE_1_5, size=4), var(FakeVariable("xmm1"))),
        compare("MLIL_FCMP_UO", var(FakeVariable("zmm0")), float_const(3.5, _DOUBLE_3_5)),
        compare("MLIL_FCMP_LT", var(FakeVariable("zmm0")), float_const(3.5, _DOUBLE_3_5)),
    )
    assert rows == [
        {
            "address": "0x7010",
            "operator": "f!=",
            "constant": "0x400c000000000000",
            "char": None,
            "subject": {"kind": "variable", "variable": "zmm0"},
            "subject_text": "zmm0",
            "float_constant": "3.5",
        },
        {
            "address": "0x7020",
            "operator": "f==",
            "constant": "0x3fc00000",
            "char": None,
            "subject": {"kind": "variable", "variable": "xmm1"},
            "subject_text": "xmm1",
            "float_constant": "1.5",
        },
    ]


@pytest.mark.parametrize(
    ("operation", "operator", "mirrored"),
    [
        ("MLIL_FCMP_LT", "f<", "f>"),
        ("MLIL_FCMP_LE", "f<=", "f>="),
        ("MLIL_FCMP_GE", "f>=", "f<="),
        ("MLIL_FCMP_GT", "f>", "f<"),
    ],
)
def test_all_reports_ordered_float_comparisons_on_either_side(
    operation: str, operator: str, mirrored: str
) -> None:
    subject = var(FakeVariable("zmm0"))
    number = float_const(3.5, _DOUBLE_3_5)
    rows = _rows(
        compare(operation, subject, number), compare(operation, number, subject), operators="all"
    )
    assert [(row["operator"], row["float_constant"]) for row in rows] == [
        (operator, "3.5"),
        (mirrored, "3.5"),
    ]
    assert "signed_constant" not in rows[0]


def test_a_float_width_without_an_ieee_format_states_no_number() -> None:
    extended = float_const(3.5, 0x4000E000000000000000, size=10)
    rows = _rows(compare("MLIL_FCMP_E", var(FakeVariable("st0")), extended))
    assert (rows[0]["constant"], rows[0]["float_constant"]) == ("0x4000e000000000000000", None)


def test_integer_rows_carry_no_float_reading() -> None:
    rows = _rows(compare("MLIL_CMP_E", var(FakeVariable("value")), const(0x41)))
    assert "float_constant" not in rows[0]


def _carriers(parameter: FakeVariable, others: list[FakeVariable], ssa: FakeMLILSSA) -> list[Any]:
    plain = [
        instruction.non_ssa_form
        for instruction in ssa.instructions
        if instruction.operation == FakeMediumLevelILOperation.MLIL_SET_VAR_SSA
    ]
    mlil = FakeMLILInstructions(plain, ssa_form=ssa)
    function = FakeFunction("copies", 0x1000, 0x1100, mlil=mlil, vars=[parameter, *others])
    _, tool = get_tool("rex_parameter_variables")
    result = tool(_call(FakeBinaryView(functions=[function])), function=0x1000, parameter="arg1")
    return result["carriers"]


def test_carriers_follow_a_copy_chain_through_every_hop() -> None:
    arg1, var_2c, rax, var_c = (FakeVariable(name) for name in ("arg1", "var_2c", "rax", "var_c"))
    ssa = FakeMLILSSA(
        [
            set_var_ssa(
                0x1227,
                FakeSSAVariable(var_2c, 1),
                var_ssa(FakeSSAVariable(arg1, 0)),
                "var_2c = arg1",
            ),
            set_var_ssa(
                0x122E, FakeSSAVariable(rax, 1), var_ssa(FakeSSAVariable(var_2c, 1)), "rax = var_2c"
            ),
            set_var_ssa(
                0x1231,
                FakeSSAVariable(var_c, 1),
                zero_extend(var_ssa(FakeSSAVariable(rax, 1))),
                "var_c = zx.q(rax)",
            ),
        ]
    )
    assert _carriers(arg1, [var_2c, rax, var_c], ssa) == [
        {"variable": "var_2c", "address": "0x1227", "text": "var_2c = arg1"},
        {"variable": "rax", "address": "0x122e", "text": "rax = var_2c"},
        {"variable": "var_c", "address": "0x1231", "text": "var_c = zx.q(rax)"},
    ]


def test_carriers_exclude_computed_values_and_truncations() -> None:
    arg1, sum_, low = FakeVariable("arg1"), FakeVariable("sum"), FakeVariable("low")
    entry = var_ssa(FakeSSAVariable(arg1, 0))
    ssa = FakeMLILSSA(
        [
            set_var_ssa(0x1010, FakeSSAVariable(sum_, 1), add(entry, const(1)), "sum = arg1 + 1"),
            set_var_ssa(0x1020, FakeSSAVariable(low, 1), low_part(entry), "low = arg1.b"),
        ]
    )
    assert _carriers(arg1, [sum_, low], ssa) == []


def test_carriers_skip_a_redefined_parameter_version() -> None:
    arg1, copy = FakeVariable("arg1"), FakeVariable("copy")
    ssa = FakeMLILSSA(
        [
            set_var_ssa(
                0x1010,
                FakeSSAVariable(arg1, 1),
                add(var_ssa(FakeSSAVariable(arg1, 0)), const(1)),
                "arg1 = arg1 + 1",
            ),
            set_var_ssa(
                0x1020, FakeSSAVariable(copy, 1), var_ssa(FakeSSAVariable(arg1, 1)), "copy = arg1"
            ),
        ]
    )
    assert _carriers(arg1, [copy], ssa) == []


def test_carriers_pass_a_phi_only_when_every_source_carries_the_parameter() -> None:
    arg1, merged, mixed, after, other = (
        FakeVariable(name) for name in ("arg1", "merged", "mixed", "after", "other")
    )
    entry = FakeSSAVariable(arg1, 0)
    left, right = FakeSSAVariable(merged, 1), FakeSSAVariable(merged, 2)
    ssa = FakeMLILSSA(
        [
            set_var_ssa(0x1010, left, var_ssa(entry), "merged = arg1"),
            set_var_ssa(0x1020, right, var_ssa(entry), "merged = arg1"),
            set_var_ssa(0x1030, FakeSSAVariable(other, 1), const(5), "other = 5"),
            phi(0x1040, FakeSSAVariable(merged, 3), [left, right]),
            phi(0x1040, FakeSSAVariable(mixed, 1), [left, FakeSSAVariable(other, 1)]),
            set_var_ssa(
                0x1050,
                FakeSSAVariable(after, 1),
                var_ssa(FakeSSAVariable(merged, 3)),
                "after = merged",
            ),
            set_var_ssa(
                0x1060,
                FakeSSAVariable(after, 2),
                var_ssa(FakeSSAVariable(mixed, 1)),
                "after = mixed",
            ),
        ]
    )
    assert _carriers(arg1, [merged, mixed, after, other], ssa) == [
        {"variable": "merged", "address": "0x1010", "text": "merged = arg1"},
        {"variable": "merged", "address": "0x1020", "text": "merged = arg1"},
        {"variable": "after", "address": "0x1050", "text": "after = merged"},
    ]


def test_carriers_match_the_parameter_by_identity_not_by_name() -> None:
    arg1, shadow, copy = FakeVariable("arg1"), FakeVariable("arg1_copy"), FakeVariable("copy")
    shadow.name = "arg1"
    ssa = FakeMLILSSA(
        [
            set_var_ssa(
                0x1010, FakeSSAVariable(copy, 1), var_ssa(FakeSSAVariable(shadow, 0)), "copy = arg1"
            )
        ]
    )
    assert _carriers(arg1, [copy], ssa) == []


def test_carriers_fail_with_no_mlil_when_the_core_gives_no_ssa_form() -> None:
    mlil = FakeMLILInstructions([])
    mlil.ssa_form = None  # ty: ignore[invalid-assignment]
    arg1 = FakeVariable("arg1")
    function = FakeFunction("copies", 0x1000, 0x1100, mlil=mlil, vars=[arg1])
    _, tool = get_tool("rex_parameter_variables")
    with pytest.raises(FakeToolError) as error:
        tool(_call(FakeBinaryView(functions=[function])), function=0x1000, parameter="arg1")
    assert error.value.code == "no_mlil"


def test_constraints_sort_by_address_value_not_by_its_text() -> None:
    subject = FakeVariable("value")
    late = branch(0x10000, compare("MLIL_CMP_E", var(subject), const(1)))
    early = branch(0x2000, compare("MLIL_CMP_E", var(subject), const(2)))
    function = FakeFunction("order", 0x1000, 0x20000, mlil=FakeMLILInstructions([late, early]))
    _, constraints = get_tool("rex_function_constraints")
    rows = constraints(_call(FakeBinaryView(functions=[function])), function=0x1000)["constraints"]
    assert [row["address"] for row in rows] == ["0x2000", "0x10000"]


def test_carriers_skip_a_field_write_of_the_parameter_into_another_variable() -> None:
    arg1, holder, copy = FakeVariable("arg1"), FakeVariable("var_18"), FakeVariable("copy")
    written = FakeSSAVariable(holder, 2)
    field = FakeInstruction(
        "MLIL_SET_VAR_SSA_FIELD", 0x1010, dest=written, src=var_ssa(FakeSSAVariable(arg1, 0))
    )
    ssa = FakeMLILSSA(
        [field, set_var_ssa(0x1020, FakeSSAVariable(copy, 1), var_ssa(written), "copy = var_18")]
    )
    assert _carriers(arg1, [holder, copy], ssa) == []


def test_constraints_at_one_address_keep_the_core_order() -> None:
    subject = FakeVariable("value")
    first = branch(0x2000, compare("MLIL_CMP_E", var(subject), const(2)))
    second = branch(0x2000, compare("MLIL_CMP_E", var(subject), const(1)))
    function = FakeFunction("same", 0x2000, 0x2100, mlil=FakeMLILInstructions([first, second]))
    _, constraints = get_tool("rex_function_constraints")
    rows = constraints(_call(FakeBinaryView(functions=[function])), function=0x2000)["constraints"]
    assert [row["constant"] for row in rows] == ["0x2", "0x1"]
