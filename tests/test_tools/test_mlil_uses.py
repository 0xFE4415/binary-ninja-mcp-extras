from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from helpers import NO_ALTERNATIVES, FakeToolError, _call, _run_uses, _uses_view, get_tool
from helpers_dataflow import (
    FakeInstruction,
    FakeMLILInstructions,
    _flag_variable,
    _stack_variable,
    add,
    branch,
    compare,
    const,
    load,
    set_var,
    sign_extend,
    var,
)
from helpers_uidf import FakeVariable, FakeVariableSourceType
from helpers_view import (
    FakeArchitecture,
    FakeBinaryView,
    FakeFunction,
)
from hypothesis import given
from hypothesis import strategies as st


def _read_of(variable: FakeVariable, address: int = 0x1030) -> FakeInstruction:
    return branch(address, compare("MLIL_CMP_NE", var(variable), const(0x68)))


def _no_uses_report(name: str, definitions: list[str], register: str = "rax") -> dict[str, Any]:
    return {
        "variable": name,
        "storage": {"source": "register", "register": register},
        "type": "int64_t",
        "definitions": definitions,
        "total": 0,
        "truncated": False,
        "uses": [],
    }


def _two_use_view() -> FakeBinaryView:
    arg_40 = FakeVariable(
        "arg_40",
        source_type=FakeVariableSourceType.StackVariableSourceType,
        storage=0x40,
        type_string="int32_t",
    )
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
        "function": {"start": "0x1000", "name": "check", **NO_ALTERNATIVES},
        "definition_site": "0x1020",
        "variables": [
            {
                "variable": "arg_40",
                "storage": {"source": "stack", "stack_offset": 64},
                "type": "int32_t",
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
    high, low = FakeVariable("high", storage=100), FakeVariable("low", storage=99)
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


@pytest.mark.parametrize(
    "instructions",
    [[], [branch(0x1020, compare("MLIL_CMP_NE", const(1), const(2)))]],
    ids=["no_instructions", "instructions_without_definitions"],
)
def test_uses_say_plainly_when_the_function_defines_no_variables(
    instructions: list[FakeInstruction],
) -> None:
    with pytest.raises(FakeToolError) as error:
        _run_uses(_uses_view(instructions, {}), address=0x1020)
    assert error.value.code == "no_definition"
    assert error.value.message == (
        "no MLIL variable definition at 0x1020 in check; the function defines no MLIL variables"
    )


@pytest.mark.parametrize(
    ("site_count", "more"),
    [(1, ""), (10, ""), (11, " (+1 more)")],
)
def test_uses_missing_definition_lists_the_sites_up_to_the_cap(site_count: int, more: str) -> None:
    definitions = [
        set_var(0x1100 + index * 0x10, FakeVariable(f"v{index}"), const(index))
        for index in range(site_count)
    ]
    recorded = {definition.dest: [definition] for definition in definitions}
    mlil = FakeMLILInstructions(definitions, definitions=recorded)
    view = FakeBinaryView(functions=[FakeFunction("check", 0x1000, 0x1200, mlil=mlil)])
    with pytest.raises(FakeToolError) as error:
        _run_uses(view, address=0x1008)
    listed = ", ".join(hex(0x1100 + index * 0x10) for index in range(min(site_count, 10)))
    assert error.value.message == (
        "no MLIL variable definition at 0x1008 in check; "
        f"variables are defined at: {listed}{more}; "
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
    high, low = FakeVariable("high", storage=100), FakeVariable("low", storage=99)
    split = FakeInstruction("MLIL_SET_VAR_SPLIT", 0x1020, high=high, low=low, src=const(1))
    view = _uses_view(
        [split, _read_of(low)],
        definitions={low: [split], high: [split]},
        uses={low: [_read_of(low)]},
    )
    assert _run_uses(view)["variables"] == [
        _no_uses_report("high", ["0x1020"], register="rdx"),
        {
            **_no_uses_report("low", ["0x1020"], register="rcx"),
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
    rax = FakeVariable("rax")
    rcx = FakeVariable("rcx", storage=99)
    rdx = FakeVariable("rdx", storage=100)
    call = FakeInstruction(operation, 0x1020, output=[rax, rcx, rdx])
    view = _uses_view([call], {rdx: [call], rax: [call], rcx: [call]})
    assert _run_uses(view)["variables"] == [
        _no_uses_report("rax", ["0x1020"]),
        _no_uses_report("rcx", ["0x1020"], register="rcx"),
        _no_uses_report("rdx", ["0x1020"], register="rdx"),
    ]


def test_uses_accept_a_tailcall_clobber_as_a_definition_site() -> None:
    rax = FakeVariable("rax")
    tailcall = FakeInstruction("MLIL_TAILCALL", 0x1020, output=[rax])
    assert _run_uses(_uses_view([tailcall], {rax: [tailcall]}))["variables"] == [
        _no_uses_report("rax", ["0x1020"])
    ]


def test_uses_report_a_forced_version_as_a_definition() -> None:
    zmm0 = FakeVariable("zmm0_1", storage=333)
    forced = FakeInstruction("MLIL_FORCE_VER", 0x1020, dest=zmm0)
    assert _run_uses(_uses_view([forced], {zmm0: [forced]}))["variables"] == [
        _no_uses_report("zmm0_1", ["0x1020"], register="zmm0")
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
    rax, rcx = FakeVariable("rax"), FakeVariable("rcx", storage=99)
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[rax, rcx])
    view = _uses_view([call], {rax: [call], rcx: [call]})
    assert _run_uses(view, variable="rcx")["variables"] == [
        _no_uses_report("rcx", ["0x1020"], register="rcx")
    ]


def _category_view() -> tuple[FakeBinaryView, list[FakeVariable]]:
    first = _stack_variable("category", 8)
    second = _stack_variable("category", 16)
    register = FakeVariable("category", storage=105, type_string="int32_t")
    rax = FakeVariable("rax", type_string="char*")
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[first, second, register, rax])
    view = _uses_view([call], {first: [call], second: [call], register: [call], rax: [call]})
    return view, [first, second, register, rax]


def _category_reports() -> list[dict[str, Any]]:
    return [
        {
            "variable": "category",
            "storage": {"source": "stack", "stack_offset": 8},
            "type": "int32_t",
            "definitions": ["0x1020"],
            "total": 0,
            "truncated": False,
            "uses": [],
        },
        {
            "variable": "category",
            "storage": {"source": "stack", "stack_offset": 16},
            "type": "int32_t",
            "definitions": ["0x1020"],
            "total": 0,
            "truncated": False,
            "uses": [],
        },
        {
            "variable": "category",
            "storage": {"source": "register", "register": "rdi"},
            "type": "int32_t",
            "definitions": ["0x1020"],
            "total": 0,
            "truncated": False,
            "uses": [],
        },
    ]


def test_uses_tell_same_named_variables_apart_by_storage() -> None:
    view, _ = _category_view()
    reports = _run_uses(view)["variables"]
    assert reports == [
        *_category_reports(),
        {**_no_uses_report("rax", ["0x1020"]), "type": "char*"},
    ]


def test_uses_filter_returns_every_same_named_variable_and_no_other() -> None:
    view, _ = _category_view()
    assert _run_uses(view, variable="category")["variables"] == _category_reports()
    assert _run_uses(view, variable="rax")["variables"] == [
        {**_no_uses_report("rax", ["0x1020"]), "type": "char*"}
    ]


def test_uses_tell_same_named_same_storage_variables_apart_by_type() -> None:
    narrow = FakeVariable("category", storage=105, type_string="int32_t")
    wide = FakeVariable("category", storage=105, type_string="int64_t")
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[narrow, wide])
    view = _uses_view([call], {narrow: [call], wide: [call]})
    reports = _run_uses(view, variable="category")["variables"]
    assert [(report["storage"], report["type"]) for report in reports] == [
        ({"source": "register", "register": "rdi"}, "int32_t"),
        ({"source": "register", "register": "rdi"}, "int64_t"),
    ]


def test_uses_keep_one_entry_for_a_variable_the_core_lists_twice() -> None:
    first = _stack_variable("category", 8)
    second = _stack_variable("category", 16)
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[first, second, first])
    view = _uses_view([call], {first: [call], second: [call]})
    assert [report["storage"] for report in _run_uses(view)["variables"]] == [
        {"source": "stack", "stack_offset": 8},
        {"source": "stack", "stack_offset": 16},
    ]


@pytest.mark.parametrize(
    ("variable", "storage"),
    [
        (FakeVariable("v", storage=105), {"source": "register", "register": "rdi"}),
        (FakeVariable("v", storage=2147483678), {"source": "register", "register": "temp30"}),
        (_stack_variable("v", 8), {"source": "stack", "stack_offset": 8}),
        (_stack_variable("v", -8), {"source": "stack", "stack_offset": -8}),
        (_stack_variable("v", 0), {"source": "stack", "stack_offset": 0}),
        (
            FakeVariable("v", source_type=FakeVariableSourceType.FlagVariableSourceType, storage=6),
            {"source": "flag", "flag": "z"},
        ),
        (_flag_variable(0), {"source": "flag", "flag": "c"}),
        (_flag_variable(0x7FFFFFFF), {"source": "flag", "flag": "flag2147483647"}),
        (_flag_variable(0x80000000), {"source": "flag", "flag": "temp flag 0"}),
        (_flag_variable(0x80000001), {"source": "flag", "flag": "temp flag 1"}),
        (_flag_variable(0x8000001E), {"source": "flag", "flag": "temp flag 30"}),
        (_flag_variable(0xFFFFFFFF), {"source": "flag", "flag": "temp flag 2147483647"}),
        (
            FakeVariable(
                "v",
                source_type=FakeVariableSourceType.CompositeReturnValueSourceType,
                storage=3,
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
def test_uses_report_the_storage_of_every_variable_source_type(
    variable: FakeVariable, storage: dict[str, Any]
) -> None:
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[variable])
    [report] = _run_uses(_uses_view([call], {variable: [call]}))["variables"]
    assert report["storage"] == storage
    assert set(report) == {
        "variable",
        "storage",
        "type",
        "definitions",
        "total",
        "truncated",
        "uses",
    }


def test_uses_reject_a_variable_source_type_the_plugin_does_not_know() -> None:
    variable = FakeVariable("v")
    variable.source_type = 99  # ty: ignore[invalid-assignment]
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[variable])
    with pytest.raises(ValueError, match=r"^unknown variable source type 99$"):
        _run_uses(_uses_view([call], {variable: [call]}))


def test_uses_resolve_register_and_flag_names_through_the_function_architecture() -> None:
    register = FakeVariable("v", storage=98)
    flag = FakeVariable("f", source_type=FakeVariableSourceType.FlagVariableSourceType, storage=6)
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[register, flag])
    mlil = FakeMLILInstructions([call], definitions={register: [call], flag: [call]})
    function_arch = FakeArchitecture("arm64", {98: "x0"}, {6: "zf"})
    function = FakeFunction("check", 0x1000, 0x1100, mlil=mlil, arch=function_arch)
    view = FakeBinaryView(
        functions=[function], arch=FakeArchitecture("x86_64", {98: "view_reg"}, {6: "view_flag"})
    )
    reports = _run_uses(view)["variables"]
    assert [report["storage"] for report in reports] == [
        {"source": "register", "register": "x0"},
        {"source": "flag", "flag": "zf"},
    ]


@pytest.mark.parametrize(
    ("length", "rendered"),
    [(512, "t" * 512), (513, "t" * 512 + "... [1 chars truncated]")],
)
def test_uses_bound_the_rendered_variable_type(length: int, rendered: str) -> None:
    variable = FakeVariable("v", type_string="t" * length)
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[variable])
    [report] = _run_uses(_uses_view([call], {variable: [call]}))["variables"]
    assert report["type"] == rendered


def test_uses_filter_by_exact_name_not_prefix() -> None:
    rax, rcx = FakeVariable("rax"), FakeVariable("rcx")
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[rax, rcx])
    view = _uses_view([call], {rax: [call], rcx: [call]})
    with pytest.raises(FakeToolError) as error:
        _run_uses(view, variable="r")
    assert error.value.code == "no_variable"


def _no_variable_message(*variables: FakeVariable) -> str:
    call = FakeInstruction("MLIL_CALL", 0x1020, output=list(variables))
    view = _uses_view([call], {variable: [call] for variable in variables})
    with pytest.raises(FakeToolError) as error:
        _run_uses(view, variable="missing")
    assert error.value.code == "no_variable"
    return error.value.message


def test_no_variable_tells_same_named_variables_apart_by_storage() -> None:
    message = _no_variable_message(
        _stack_variable("category", 8), FakeVariable("category", storage=105)
    )
    assert message == (
        "no variable named 'missing' is defined at 0x1020 in check; "
        "defined there: category (stack +0x8), category (rdi)"
    )


@pytest.mark.parametrize(
    ("variable", "text"),
    [
        (FakeVariable("v", storage=105), "v (rdi)"),
        (_stack_variable("v", 8), "v (stack +0x8)"),
        (_stack_variable("v", -8), "v (stack -0x8)"),
        (_stack_variable("v", 0), "v (stack +0x0)"),
        (_stack_variable("v", 0x1F0), "v (stack +0x1f0)"),
        (_flag_variable(6), "f (z)"),
        (_flag_variable(0x80000003), "f (temp flag 3)"),
        (
            FakeVariable(
                "v", source_type=FakeVariableSourceType.CompositeReturnValueSourceType, storage=3
            ),
            "v (composite_return_value 3)",
        ),
        (
            FakeVariable(
                "v", source_type=FakeVariableSourceType.CompositeParameterSourceType, storage=4
            ),
            "v (composite_parameter 4)",
        ),
    ],
)
def test_no_variable_renders_each_storage_kind_like_the_report(
    variable: FakeVariable, text: str
) -> None:
    assert _no_variable_message(variable).endswith(f"defined there: {text}")


def test_no_variable_bounds_each_listed_name_before_its_storage() -> None:
    long_variable = FakeVariable("n" * 65, storage=105)
    message = _no_variable_message(long_variable)
    assert message.endswith("defined there: " + "n" * 64 + "... [1 chars truncated] (rdi)")


def test_no_variable_lists_a_variable_the_core_defines_twice_once() -> None:
    variable = _stack_variable("category", 8)
    assert _no_variable_message(variable, variable).endswith("defined there: category (stack +0x8)")


def test_no_variable_resolves_register_names_through_the_function_architecture() -> None:
    variable = FakeVariable("v", storage=98)
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[variable])
    mlil = FakeMLILInstructions([call], definitions={variable: [call]})
    function = FakeFunction(
        "check", 0x1000, 0x1100, mlil=mlil, arch=FakeArchitecture("arm64", {98: "x0"}, {})
    )
    with pytest.raises(FakeToolError) as error:
        _run_uses(FakeBinaryView(functions=[function]), variable="missing")
    assert error.value.message.endswith("defined there: v (x0)")


def test_uses_reject_a_variable_not_defined_at_the_address() -> None:
    rax, rcx = FakeVariable("rax"), FakeVariable("rcx", storage=99)
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[rax, rcx])
    view = _uses_view([call], {rax: [call], rcx: [call]})
    with pytest.raises(FakeToolError) as error:
        _run_uses(view, variable="rdx")
    assert error.value.code == "no_variable"
    assert error.value.message == (
        "no variable named 'rdx' is defined at 0x1020 in check; defined there: rax (rax), rcx (rcx)"
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


def test_uses_without_mlil_fail_with_no_mlil() -> None:
    function = FakeFunction("bare", 0x2000, 0x2100)
    view = FakeBinaryView(functions=[function])
    _, uses = get_tool("rex_mlil_uses")
    with pytest.raises(FakeToolError) as error:
        uses(_call(view), function=0x2000, address=0x2004)
    assert error.value.code == "no_mlil"
    assert "run bn_analysis_update_and_wait" in error.value.message


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


@given(index=st.integers(min_value=0, max_value=0x7FFFFFFF))
def test_a_temp_flag_display_names_the_exact_storage_it_stands_for(index: int) -> None:
    variable = _flag_variable(0x80000000 | index)
    call = FakeInstruction("MLIL_CALL", 0x1020, output=[variable])
    [report] = _run_uses(_uses_view([call], {variable: [call]}))["variables"]
    assert report["storage"] == {"source": "flag", "flag": f"temp flag {index}"}
