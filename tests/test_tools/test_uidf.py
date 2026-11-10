from __future__ import annotations

from typing import override

import pytest
from helpers import (
    NO_ALTERNATIVES,
    FakeParsingToolCall,
    FakeToolError,
    _call,
    get_tool,
)
from helpers_uidf import (
    FakeMediumLevelIL,
    FakePossibleValueSet,
    FakeRegisterValueType,
    FakeVariable,
)
from helpers_view import (
    FakeAnalysisProgress,
    FakeAnalysisState,
    FakeBinaryView,
    FakeFunction,
    RenderableText,
)
from hypothesis import given
from hypothesis import strategies as st

from binja_plugin import tools
from binja_plugin.tools import uidf as uidf_tools


def _variable(function: FakeFunction, name: str) -> FakeVariable:
    return next(item for item in function.vars if item.name == name)


def _inform(function: FakeFunction, name: str, address: int, rendered: str) -> None:
    function.set_user_var_value(
        _variable(function, name),
        address,
        FakePossibleValueSet(FakeRegisterValueType.ConstantValue, rendered),
        after=True,
    )


def _uidf_view(
    progress: list[FakeAnalysisProgress] | None = None,
) -> tuple[FakeBinaryView, FakeFunction]:
    rax_1 = FakeVariable("rax_1")
    var_10 = FakeVariable("var_10")
    main = FakeFunction(
        "main",
        0x1100,
        0x1200,
        hlil=RenderableText("int32_t rax_1 = 1\nif (rax_1 == 1)\n    return 0\nreturn 1"),
        vars=[rax_1, var_10, FakeVariable("argc")],
        mlil=FakeMediumLevelIL({rax_1: [0x1104], var_10: [0x1190, 0x1196, 0x119C]}),
    )
    handler_rax = FakeVariable("rax_1")
    handler = FakeFunction(
        "handler",
        0x2000,
        0x2100,
        hlil=RenderableText("return 0"),
        vars=[handler_rax],
        mlil=FakeMediumLevelIL({handler_rax: [0x2004]}),
    )
    view = FakeBinaryView(functions=[main, handler], analysis_progress_sequence=progress)
    return view, main


class FakeClock:
    """Deterministic clock for the settling loop: scripted monotonic ticks in order, then
    the time the sleeps accumulated; sleep records the exact milliseconds requested."""

    def __init__(self, ticks: list[float] | None = None) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []
        self._ticks: list[float] = list(ticks) if ticks is not None else []

    def monotonic(self) -> float:
        if self._ticks:
            return self._ticks.pop(0)
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds * 1000)
        self.now += seconds


def _patch_time(monkeypatch: pytest.MonkeyPatch, clock: FakeClock) -> None:
    monkeypatch.setattr("time.sleep", clock.sleep)
    monkeypatch.setattr("time.monotonic", clock.monotonic)


def test_uidf_set_informs_a_constant_and_renders_hlil(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_time(monkeypatch, FakeClock())
    view, main = _uidf_view()
    _, uidf_set = get_tool("rex_uidf_set")
    result = uidf_set(_call(view), 0x1100, "rax_1", "0x10")
    assert result == {
        "function": {"start": "0x1100", "name": "main", **NO_ALTERNATIVES},
        "variable": "rax_1",
        "definition_site": "0x1104",
        "value": {"state": "ConstantValue", "rendered": "<const 0x10>"},
        "analysis_complete": True,
        "lines": ["int32_t rax_1 = 1", "if (rax_1 == 1)", "    return 0", "return 1"],
        "truncated": False,
    }
    assert view.update_analysis_calls == 1
    # The spec is parsed at the definition site, so "$here" resolves there.
    assert view.possible_value_parses == [("0x10", FakeRegisterValueType.ConstantValue, 0x1104)]
    variable = _variable(main, "rax_1")
    assert main.set_user_var_value_calls == [
        (variable, 0x1104, main.user_var_values[variable][0x1104], True)
    ]
    assert str(main.user_var_values[variable][0x1104]) == "<const 0x10>"
    clipped = uidf_set(_call(view), 0x1100, "rax_1", "0x10", max_lines=2)
    assert clipped["lines"] == ["int32_t rax_1 = 1", "if (rax_1 == 1)"]
    assert clipped["truncated"] is True


def test_uidf_set_many_applies_valid_items_and_reanalyzes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_time(monkeypatch, FakeClock())
    view, main = _uidf_view()
    _, uidf_set_many = get_tool("rex_uidf_set_many")
    result = uidf_set_many(
        FakeParsingToolCall(view),
        0x1100,
        [
            {"variable": "rax_1", "value": "0x10"},
            {"variable": "missing", "value": "1"},
            {"variable": "var_10", "value": "2"},
            {"variable": "var_10", "def_address": 0x1196, "value": "3", "state": "ConstantValue"},
        ],
    )
    assert result["applied"] == 2
    assert result["failed"] == 2
    assert result["total"] == 4
    assert result["results"][0] == {
        "index": 0,
        "variable": "rax_1",
        "definition_site": "0x1104",
        "value": {"state": "ConstantValue", "rendered": "<const 0x10>"},
        "ok": True,
    }
    assert result["results"][1]["error"]["code"] == "no_variable"
    assert result["results"][2]["error"]["code"] == "ambiguous_definition"
    assert result["results"][3]["definition_site"] == "0x1196"
    assert view.update_analysis_calls == 1
    assert len(main.set_user_var_value_calls) == 2
    assert [str(entry[2]) for entry in main.set_user_var_value_calls] == [
        "<const 0x10>",
        "<const 0x3>",
    ]
    assert result["analysis_complete"] is True
    assert result["lines"] == [
        "int32_t rax_1 = 1",
        "if (rax_1 == 1)",
        "    return 0",
        "return 1",
    ]


def test_uidf_set_many_validates_limits_and_item_fields() -> None:
    view, _ = _uidf_view()
    _, uidf_set_many = get_tool("rex_uidf_set_many")
    with pytest.raises(FakeToolError) as exc:
        uidf_set_many(_call(view), 0x1100, {"variable": "rax_1", "value": "1"})
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "items must be a list of uidf item objects"
    with pytest.raises(FakeToolError) as exc:
        uidf_set_many(_call(view), 0x1100, [])
    assert exc.value.code == "invalid_params"
    assert f"between 1 and {uidf_tools._MAX_UIDF_BATCH}" in exc.value.message
    result = uidf_set_many(
        FakeParsingToolCall(view),
        0x1100,
        [
            {"variable": "rax_1", "value": "garbage!!"},
            {"variable": "rax_1", "value": "1", "unexpected": True, "mystery": 2},
            "not-an-object",
            {"variable": 3, "value": "1"},
            {"variable": "rax_1", "value": 3},
            {"variable": "rax_1", "value": "1", "def_address": True},
            {"variable": "rax_1", "value": "1", "def_address": "bad"},
            {"variable": "rax_1", "value": "1", "state": 2},
            {"variable": "rax_1", "value": "1", "state": "Bogus"},
            {"value": "1"},
        ],
    )
    assert result["results"] == [
        {
            "index": 0,
            "variable": "rax_1",
            "ok": False,
            "error": {
                "code": "invalid_params",
                "message": (
                    "Invalid value parameter 'value': invalid literal for int() with base 16: "
                    "'garbage!!'"
                ),
            },
        },
        {
            "index": 1,
            "variable": "rax_1",
            "ok": False,
            "error": {
                "code": "invalid_params",
                "message": "unknown field(s): mystery, unexpected",
            },
        },
        {
            "index": 2,
            "variable": "'not-an-object'",
            "ok": False,
            "error": {"code": "invalid_params", "message": "each item must be a JSON object"},
        },
        {
            "index": 3,
            "variable": "3",
            "ok": False,
            "error": {"code": "invalid_params", "message": "variable must be a non-empty string"},
        },
        {
            "index": 4,
            "variable": "rax_1",
            "ok": False,
            "error": {"code": "invalid_params", "message": "value must be a non-empty string"},
        },
        {
            "index": 5,
            "variable": "rax_1",
            "ok": False,
            "error": {
                "code": "invalid_params",
                "message": "def_address must be an integer or string",
            },
        },
        {
            "index": 6,
            "variable": "rax_1",
            "ok": False,
            "error": {
                "code": "invalid_params",
                "message": "bad definition address: unparsable address expression 'bad'",
            },
        },
        {
            "index": 7,
            "variable": "rax_1",
            "ok": False,
            "error": {"code": "invalid_params", "message": "state must be a string"},
        },
        {
            "index": 8,
            "variable": "rax_1",
            "ok": False,
            "error": {
                "code": "invalid_params",
                "message": (
                    "Invalid state parameter 'state': must be one of ConstantValue, "
                    "ConstantPointerValue, StackFrameOffset, SignedRangeValue, "
                    "UnsignedRangeValue, InSetOfValues, NotInSetOfValues"
                ),
            },
        },
        {
            "index": 9,
            "variable": "<invalid item>",
            "ok": False,
            "error": {"code": "invalid_params", "message": "variable must be a non-empty string"},
        },
    ]
    assert result["applied"] == 0
    assert view.update_analysis_calls == 0


@given(
    item=st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(max_size=24),
        lambda children: st.lists(children, max_size=4),
        max_leaves=8,
    )
)
def test_uidf_set_many_rejects_non_object_items_with_a_stable_result_shape(item: object) -> None:
    view, _ = _uidf_view()
    _, uidf_set_many = get_tool("rex_uidf_set_many")
    result = uidf_set_many(_call(view), 0x1100, [item])
    assert result["results"] == [
        {
            "index": 0,
            "variable": repr(item),
            "ok": False,
            "error": {"code": "invalid_params", "message": "each item must be a JSON object"},
        }
    ]
    assert result["applied"] == 0


def test_uidf_set_many_reports_core_apply_failures_without_reanalysis() -> None:
    view, main = _uidf_view()
    main.set_user_var_value_error = Exception("core refused")
    _, uidf_set_many = get_tool("rex_uidf_set_many")
    result = uidf_set_many(
        _call(view),
        0x1100,
        [{"variable": "rax_1", "value": "1"}],
    )
    assert result["applied"] == 0
    assert result["failed"] == 1
    assert result["results"][0]["error"] == {
        "code": "set_failed",
        "message": "could not inform 'rax_1': core refused",
    }
    assert view.update_analysis_calls == 0


class _ExplodingValue(FakePossibleValueSet):
    @override
    def __str__(self) -> str:
        raise RuntimeError("no str")


class _CountingValue(FakePossibleValueSet):
    renders = 0

    @override
    def __str__(self) -> str:
        type(self).renders += 1
        return super().__str__()


class _SpecialValueView(FakeBinaryView):
    @override
    def parse_possiblevalueset(
        self, value: str, state: FakeRegisterValueType, here: int = 0
    ) -> FakePossibleValueSet:
        if value == "boom":
            return _ExplodingValue(state, "<boom>")
        if value == "count":
            return _CountingValue(state, "<counted>")
        return super().parse_possiblevalueset(value, state, here)


def _special_value_view() -> tuple[_SpecialValueView, FakeFunction]:
    _, main = _uidf_view()
    return _SpecialValueView(functions=[main]), main


@pytest.mark.parametrize(
    "items",
    [
        [{"variable": "rax_1", "value": "boom"}],
        [
            {"variable": "rax_1", "value": "boom"},
            {"variable": "var_10", "value": "2", "def_address": 0x1196},
        ],
        [
            {"variable": "rax_1", "value": "0x10"},
            {"variable": "var_10", "value": "boom", "def_address": 0x1196},
        ],
        [
            {"variable": "rax_1", "value": "0x10"},
            {"variable": "var_10", "value": "2", "def_address": 0x1196},
            {"variable": "var_10", "value": "boom", "def_address": 0x119C},
        ],
        [
            {"variable": "rax_1", "value": "0x10"},
            {"variable": "missing", "value": "1"},
            {"variable": "var_10", "value": "boom", "def_address": 0x119C},
            {"variable": "var_10", "value": "3", "def_address": 0x1196},
        ],
    ],
)
def test_uidf_set_many_stages_every_description_before_it_mutates(
    items: list[dict[str, object]],
) -> None:
    view, main = _special_value_view()
    _, uidf_set_many = get_tool("rex_uidf_set_many")
    with pytest.raises(RuntimeError, match=r"^no str$"):
        uidf_set_many(FakeParsingToolCall(view), 0x1100, items)
    assert main.set_user_var_value_calls == []
    assert main.user_var_values == {}
    assert view.update_analysis_calls == 0


def test_uidf_set_renders_the_description_before_it_informs() -> None:
    view, main = _special_value_view()
    _, uidf_set = get_tool("rex_uidf_set")
    with pytest.raises(RuntimeError, match=r"^no str$"):
        uidf_set(_call(view), 0x1100, "rax_1", "boom")
    assert main.set_user_var_value_calls == []
    assert main.user_var_values == {}
    assert view.update_analysis_calls == 0


def test_uidf_set_renders_the_value_exactly_once() -> None:
    _CountingValue.renders = 0
    view, main = _special_value_view()
    _, uidf_set = get_tool("rex_uidf_set")
    result = uidf_set(_call(view), 0x1100, "rax_1", "count")
    assert result["value"] == {"state": "ConstantValue", "rendered": "<counted>"}
    assert _CountingValue.renders == 1
    main.set_user_var_value_error = Exception("core refused")
    _CountingValue.renders = 0
    with pytest.raises(FakeToolError) as error:
        uidf_set(_call(view), 0x1100, "rax_1", "count")
    assert error.value.code == "set_failed"
    assert error.value.message == "could not inform 'rax_1': core refused"
    assert _CountingValue.renders == 1


def test_uidf_set_many_renders_each_value_exactly_once() -> None:
    _CountingValue.renders = 0
    view, main = _special_value_view()
    _, uidf_set_many = get_tool("rex_uidf_set_many")
    applied = uidf_set_many(
        FakeParsingToolCall(view), 0x1100, [{"variable": "rax_1", "value": "count"}]
    )
    assert applied["results"] == [
        {
            "index": 0,
            "variable": "rax_1",
            "definition_site": "0x1104",
            "value": {"state": "ConstantValue", "rendered": "<counted>"},
            "ok": True,
        }
    ]
    assert _CountingValue.renders == 1
    main.set_user_var_value_error = Exception("core refused")
    _CountingValue.renders = 0
    failed = uidf_set_many(
        FakeParsingToolCall(view), 0x1100, [{"variable": "rax_1", "value": "count"}]
    )
    assert failed["results"] == [
        {
            "index": 0,
            "variable": "rax_1",
            "definition_site": "0x1104",
            "value": {"state": "ConstantValue", "rendered": "<counted>"},
            "ok": False,
            "error": {
                "code": "set_failed",
                "message": "could not inform 'rax_1': core refused",
            },
        }
    ]
    assert _CountingValue.renders == 1


def test_uidf_set_many_reports_exact_rows_for_applied_staged_and_refused_items() -> None:
    view, main = _uidf_view()
    _, uidf_set_many = get_tool("rex_uidf_set_many")
    items: list[dict[str, object]] = [
        {"variable": "rax_1", "value": "0x10"},
        {"variable": "missing", "value": "1"},
        {
            "variable": "var_10",
            "value": "1:10:1",
            "def_address": 0x1196,
            "state": "UnsignedRangeValue",
        },
    ]
    result = uidf_set_many(FakeParsingToolCall(view), 0x1100, items)
    assert result["results"][0] == {
        "index": 0,
        "variable": "rax_1",
        "definition_site": "0x1104",
        "value": {"state": "ConstantValue", "rendered": "<const 0x10>"},
        "ok": True,
    }
    assert result["results"][2] == {
        "index": 2,
        "variable": "var_10",
        "definition_site": "0x1196",
        "value": {
            "state": "UnsignedRangeValue",
            "rendered": "<unsigned ranges: [<range: 0x1 to 0x10>]>",
        },
        "ok": True,
    }
    assert [entry[1] for entry in main.set_user_var_value_calls] == [0x1104, 0x1196]
    main.set_user_var_value_error = Exception("core refused")
    refused = uidf_set_many(FakeParsingToolCall(view), 0x1100, items[:1])
    assert refused["results"] == [
        {
            "index": 0,
            "variable": "rax_1",
            "definition_site": "0x1104",
            "value": {"state": "ConstantValue", "rendered": "<const 0x10>"},
            "ok": False,
            "error": {
                "code": "set_failed",
                "message": "could not inform 'rax_1': core refused",
            },
        }
    ]


def test_uidf_set_parses_ranges_and_value_sets(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_time(monkeypatch, FakeClock())
    view, _ = _uidf_view()
    _, uidf_set = get_tool("rex_uidf_set")
    unsigned = uidf_set(_call(view), 0x1100, "rax_1", "1:10:1", state="UnsignedRangeValue")
    assert unsigned["value"] == {
        "state": "UnsignedRangeValue",
        "rendered": "<unsigned ranges: [<range: 0x1 to 0x10>]>",
    }
    signed = uidf_set(_call(view), 0x1100, "rax_1", "-5:5:1", state="SignedRangeValue")
    assert signed["value"]["rendered"] == "<signed ranges: [<range: -0x5 to 0x5>]>"
    in_set = uidf_set(_call(view), 0x1100, "rax_1", "1,2,3", state="InSetOfValues")
    assert in_set["value"]["rendered"] == "<in set([0x1, 0x2, 0x3])>"
    not_in_set = uidf_set(_call(view), 0x1100, "rax_1", "0x10", state="NotInSetOfValues")
    assert not_in_set["value"]["rendered"] == "<not in set([0x10])>"
    pointer = uidf_set(_call(view), 0x1100, "rax_1", "0x400000", state="ConstantPointerValue")
    assert pointer["value"]["state"] == "ConstantPointerValue"
    # The state name reaches the parser as the matching enum member.
    assert [state for _, state, _ in view.possible_value_parses] == [
        FakeRegisterValueType.UnsignedRangeValue,
        FakeRegisterValueType.SignedRangeValue,
        FakeRegisterValueType.InSetOfValues,
        FakeRegisterValueType.NotInSetOfValues,
        FakeRegisterValueType.ConstantPointerValue,
    ]


def test_uidf_set_rejects_unparsable_values() -> None:
    view, main = _uidf_view()
    _, uidf_set = get_tool("rex_uidf_set")
    specs = (("garbage!!", "ConstantValue"), ("0x10", "UnsignedRangeValue"), ("", "ConstantValue"))
    for value, state in specs:
        with pytest.raises(FakeToolError) as exc:
            uidf_set(_call(view), 0x1100, "rax_1", value, state=state)
        assert exc.value.code == "invalid_params"
        assert "Invalid value parameter 'value'" in exc.value.message
    assert main.set_user_var_value_calls == []


def test_uidf_set_rejects_unknown_variables() -> None:
    view, main = _uidf_view()
    _, uidf_set = get_tool("rex_uidf_set")
    with pytest.raises(FakeToolError) as exc:
        uidf_set(_call(view), 0x1100, "nope", "1")
    assert exc.value.code == "no_variable"
    assert exc.value.message == (
        "no MLIL variable named 'nope' in main; variables: argc, rax_1, var_10; "
        "use bn_variable_list for the full list. "
        "Register-allocated parameters are named by their register (for example r14), "
        "not by their argument name"
    )
    # A variable the function knows but never defines in the MLIL is equally unusable, and
    # the message must not claim the name is unknown while listing it among candidates.
    with pytest.raises(FakeToolError) as exc:
        uidf_set(_call(view), 0x1100, "argc", "1")
    assert exc.value.code == "no_variable"
    assert exc.value.message == (
        "MLIL variable 'argc' in main has no MediumLevelIL definition sites; "
        "stack-passed arguments cannot be informed, inform the register that loads the value"
    )
    assert main.set_user_var_value_calls == []


def test_uidf_set_lists_up_to_the_candidate_cap_without_a_more_suffix() -> None:
    # Exactly _MAX_NAME_CANDIDATES names: each is listed in full (a 65-char name shows its
    # 64-char truncation) and no "(+N more)" suffix is appended.
    variables = [FakeVariable("L" * 65)] + [FakeVariable(f"var_{index:02d}") for index in range(39)]
    leaf = FakeFunction("leaf", 0x2000, 0x2100, vars=variables, mlil=FakeMediumLevelIL({}))
    view = FakeBinaryView(functions=[leaf])
    _, uidf_set = get_tool("rex_uidf_set")
    shown = ", ".join(
        ["L" * 64 + "... [1 chars truncated]"] + [f"var_{index:02d}" for index in range(39)]
    )
    with pytest.raises(FakeToolError) as exc:
        uidf_set(_call(view), 0x2000, "nope", "1")
    assert exc.value.code == "no_variable"
    assert exc.value.message == (
        f"no MLIL variable named 'nope' in leaf; variables: {shown}; "
        "use bn_variable_list for the full list. "
        "Register-allocated parameters are named by their register (for example r14), "
        "not by their argument name"
    )


def test_uidf_set_counts_candidates_past_the_listed_ones() -> None:
    variables = [FakeVariable(f"var_{index:02d}") for index in range(41)]
    leaf = FakeFunction("leaf", 0x2000, 0x2100, vars=variables, mlil=FakeMediumLevelIL({}))
    view = FakeBinaryView(functions=[leaf])
    _, uidf_set = get_tool("rex_uidf_set")
    with pytest.raises(FakeToolError) as exc:
        uidf_set(_call(view), 0x2000, "nope", "1")
    assert exc.value.code == "no_variable"
    assert exc.value.message.startswith("no MLIL variable named 'nope' in leaf; variables: ")
    assert "(+1 more); use bn_variable_list for the full list" in exc.value.message


def test_uidf_set_requires_def_address_for_multi_site_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_time(monkeypatch, FakeClock())
    view, main = _uidf_view()
    _, uidf_set = get_tool("rex_uidf_set")
    with pytest.raises(FakeToolError) as exc:
        uidf_set(_call(view), 0x1100, "var_10", "1")
    assert exc.value.code == "ambiguous_definition"
    assert exc.value.message == (
        "variable 'var_10' matches 3 definitions at 0x1190, 0x1196, 0x119c; "
        "pass def_address to choose one"
    )
    picked = uidf_set(_call(view), 0x1100, "var_10", "1", def_address=0x1196)
    assert picked["definition_site"] == "0x1196"
    assert _variable(main, "var_10") in main.user_var_values
    with pytest.raises(FakeToolError) as exc:
        uidf_set(_call(view), 0x1100, "var_10", "1", def_address=0x1400)
    assert exc.value.code == "definition_not_found"
    assert exc.value.message == (
        "variable 'var_10' has no definition at 0x1400; definitions: 0x1190, 0x1196, 0x119c"
    )


def test_uidf_set_rejects_same_named_variables_at_one_site() -> None:
    first, second = FakeVariable("rax_1"), FakeVariable("rax_1")
    main = FakeFunction(
        "main",
        0x1100,
        0x1200,
        vars=[first, second],
        mlil=FakeMediumLevelIL({first: [0x1104], second: [0x1104]}),
    )
    view = FakeBinaryView(functions=[main])
    _, uidf_set = get_tool("rex_uidf_set")
    with pytest.raises(FakeToolError) as exc:
        uidf_set(_call(view), 0x1100, "rax_1", "1")
    assert exc.value.code == "ambiguous_definition"
    assert exc.value.message == (
        "variable 'rax_1' matches 2 definitions at 0x1104; pass def_address to choose one"
    )
    with pytest.raises(FakeToolError) as exc:
        uidf_set(_call(view), 0x1100, "rax_1", "1", def_address=0x1104)
    assert exc.value.code == "ambiguous_definition"
    assert exc.value.message == "variable 'rax_1' matches 2 definitions at 0x1104"


def test_uidf_set_rejects_functions_without_mlil() -> None:
    leaf = FakeFunction("leaf", 0x2000, 0x2100, vars=[FakeVariable("x")])
    view = FakeBinaryView(functions=[leaf])
    _, uidf_set = get_tool("rex_uidf_set")
    with pytest.raises(FakeToolError) as exc:
        uidf_set(_call(view), 0x2000, "x", "1")
    assert exc.value.code == "no_mlil"
    assert exc.value.message == (
        "function leaf has no MediumLevelIL yet; "
        "run bn_analysis_update_and_wait (or rex_analysis_wait with a bound) and retry"
    )


def test_uidf_set_rejects_bad_function_max_lines_and_state() -> None:
    view, _ = _uidf_view()
    _, uidf_set = get_tool("rex_uidf_set")
    with pytest.raises(FakeToolError) as exc:
        uidf_set(_call(view), 0x1800, "rax_1", "1")
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "no analyzed function contains 0x1800"
    for kwargs, message in (
        ({"max_lines": 0}, "Invalid integer parameter 'max_lines': Must be at least 1"),
        (
            {"max_lines": uidf_tools._MAX_DECOMPILE_LINES + 1},
            "Invalid integer parameter 'max_lines': "
            f"Must be at most {uidf_tools._MAX_DECOMPILE_LINES}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            uidf_set(_call(view), 0x1100, "rax_1", "1", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # A state outside the schema's Literal can only arrive through a direct handler call.
    with pytest.raises(FakeToolError) as exc:
        uidf_set(_call(view), 0x1100, "rax_1", "1", state="Bogus")
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        "Invalid state parameter 'state': must be one of "
        "ConstantValue, ConstantPointerValue, StackFrameOffset, SignedRangeValue, "
        "UnsignedRangeValue, InSetOfValues, NotInSetOfValues"
    )


def test_uidf_set_wraps_core_failures() -> None:
    view, main = _uidf_view()
    main.set_user_var_value_error = Exception("core refused")
    _, uidf_set = get_tool("rex_uidf_set")
    with pytest.raises(FakeToolError) as exc:
        uidf_set(_call(view), 0x1100, "rax_1", "1")
    assert exc.value.code == "set_failed"
    assert "core refused" in exc.value.message


def test_uidf_set_returns_immediately_when_analysis_is_idle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    _patch_time(monkeypatch, clock)
    view, _ = _uidf_view()
    _, uidf_set = get_tool("rex_uidf_set")
    result = uidf_set(_call(view), 0x1100, "rax_1", "1")
    # An already idle view answers without a single poll of the analysis queue.
    assert result["analysis_complete"] is True
    assert clock.sleeps == []


def test_uidf_set_polls_until_analysis_settles(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = FakeClock([0.0, 5.0])
    _patch_time(monkeypatch, clock)
    view, _ = _uidf_view(
        [
            FakeAnalysisProgress(FakeAnalysisState.HoldState),
            FakeAnalysisProgress(FakeAnalysisState.IdleState),
        ]
    )
    _, uidf_set = get_tool("rex_uidf_set")
    result = uidf_set(_call(view), 0x1100, "rax_1", "1")
    # The wait is one slice long: the entry read reports HoldState, the read after the
    # first slice reports IdleState and ends it.
    assert result["analysis_complete"] is True
    assert clock.sleeps == [float(uidf_tools._UIDF_ANALYSIS_SLICE_MS)]


def test_uidf_set_stops_at_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    # Five Holds outlast the 10000 ms budget; the trailing Idle keeps a loop that polls
    # past the deadline from hanging the suite.
    view, _ = _uidf_view(
        [FakeAnalysisProgress(FakeAnalysisState.HoldState)] * 5
        + [FakeAnalysisProgress(FakeAnalysisState.IdleState)]
    )
    clock = FakeClock([0.0, 9.999, 10.0])
    _patch_time(monkeypatch, clock)
    _, uidf_set = get_tool("rex_uidf_set")
    result = uidf_set(_call(view), 0x1100, "rax_1", "1")
    # 9.999 s is still inside the _MAX_UIDF_ANALYSIS_WAIT_MS budget and polls; the 10.0 s
    # read is not, so the give-up costs exactly one slice, and HLIL renders regardless.
    assert result["analysis_complete"] is False
    assert result["lines"] == ["int32_t rax_1 = 1", "if (rax_1 == 1)", "    return 0", "return 1"]
    assert clock.sleeps == [float(uidf_tools._UIDF_ANALYSIS_SLICE_MS)]


def test_uidf_clear_clears_one_variable_across_sites() -> None:
    view, main = _uidf_view()
    _inform(main, "var_10", 0x1190, "<const 0x1>")
    _inform(main, "var_10", 0x1196, "<const 0x2>")
    _inform(main, "rax_1", 0x1104, "<const 0x3>")
    _, uidf_clear = get_tool("rex_uidf_clear")
    result = uidf_clear(_call(view), 0x1100, "var_10")
    assert result == {
        "function": {"start": "0x1100", "name": "main", **NO_ALTERNATIVES},
        "variable": "var_10",
        "cleared": 2,
        "definition_sites": 3,
    }
    assert view.update_analysis_calls == 1
    variable = _variable(main, "var_10")
    assert main.cleared_user_var_values == [
        (variable, 0x1190),
        (variable, 0x1196),
        (variable, 0x119C),
    ]
    assert list(main.user_var_values) == [_variable(main, "rax_1")]


def test_uidf_clear_all_for_a_function() -> None:
    view, main = _uidf_view()
    _inform(main, "var_10", 0x1190, "<const 0x1>")
    _inform(main, "rax_1", 0x1104, "<const 0x3>")
    _, uidf_clear = get_tool("rex_uidf_clear")
    assert uidf_clear(_call(view), 0x1100) == {
        "function": {"start": "0x1100", "name": "main", **NO_ALTERNATIVES},
        "variable": None,
        "cleared": 2,
    }
    assert main.cleared_all_user_var_values == 1
    assert main.user_var_values == {}


def test_uidf_clear_rejects_unknown_variables_and_wraps_core_errors() -> None:
    view, main = _uidf_view()
    _, uidf_clear = get_tool("rex_uidf_clear")
    with pytest.raises(FakeToolError) as exc:
        uidf_clear(_call(view), 0x1100, "nope")
    assert exc.value.code == "no_variable"
    main.clear_user_var_value_error = Exception("core refused")
    with pytest.raises(FakeToolError) as exc:
        uidf_clear(_call(view), 0x1100, "rax_1")
    assert exc.value.code == "clear_failed"
    assert "core refused" in exc.value.message
    main.clear_user_var_value_error = None
    main.clear_all_user_var_values_error = Exception("core refused all")
    with pytest.raises(FakeToolError) as exc:
        uidf_clear(_call(view), 0x1100)
    assert exc.value.code == "clear_failed"
    assert "core refused all" in exc.value.message


def test_uidf_clear_needs_mlil_only_for_named_variables() -> None:
    leaf = FakeFunction("leaf", 0x2000, 0x2100, vars=[FakeVariable("x")])
    view = FakeBinaryView(functions=[leaf])
    _, uidf_clear = get_tool("rex_uidf_clear")
    with pytest.raises(FakeToolError) as exc:
        uidf_clear(_call(view), 0x2000, "x")
    assert exc.value.code == "no_mlil"
    assert uidf_clear(_call(view), 0x2000) == {
        "function": {"start": "0x2000", "name": "leaf", **NO_ALTERNATIVES},
        "variable": None,
        "cleared": 0,
    }


def test_uidf_list_reports_each_informed_site() -> None:
    view, main = _uidf_view()
    handler = view.functions[1]
    _inform(main, "rax_1", 0x1104, "<const 0x9>")
    _inform(main, "var_10", 0x1196, "<const 0x1>")
    _inform(main, "var_10", 0x1190, "<const 0x2>")
    _inform(handler, "rax_1", 0x2004, "<const 0x3>")
    _, uidf_list = get_tool("rex_uidf_list")
    assert uidf_list(_call(view)) == {
        "function": None,
        "total": 4,
        "truncated": False,
        "values": [
            {
                "function": {"start": "0x1100", "name": "main"},
                "variable": "rax_1",
                "definition_site": "0x1104",
                "architecture": "x86_64",
                "state": "ConstantValue",
                "value": "<const 0x9>",
            },
            {
                "function": {"start": "0x1100", "name": "main"},
                "variable": "var_10",
                "definition_site": "0x1190",
                "architecture": "x86_64",
                "state": "ConstantValue",
                "value": "<const 0x2>",
            },
            {
                "function": {"start": "0x1100", "name": "main"},
                "variable": "var_10",
                "definition_site": "0x1196",
                "architecture": "x86_64",
                "state": "ConstantValue",
                "value": "<const 0x1>",
            },
            {
                "function": {"start": "0x2000", "name": "handler"},
                "variable": "rax_1",
                "definition_site": "0x2004",
                "architecture": "x86_64",
                "state": "ConstantValue",
                "value": "<const 0x3>",
            },
        ],
    }
    scoped = uidf_list(_call(view), 0x2000)
    assert scoped["function"] == {"start": "0x2000", "name": "handler", **NO_ALTERNATIVES}
    assert scoped["total"] == 1
    assert scoped["values"][0]["function"] == {"start": "0x2000", "name": "handler"}
    assert uidf_list(_call(view), 0x1100)["total"] == 3


def test_uidf_list_paginates_and_rejects_bad_arguments() -> None:
    view, main = _uidf_view()
    _inform(main, "rax_1", 0x1104, "<const 0x9>")
    _inform(main, "var_10", 0x1190, "<const 0x1>")
    _inform(main, "var_10", 0x1196, "<const 0x2>")
    _, uidf_list = get_tool("rex_uidf_list")
    paged = uidf_list(_call(view), limit=2, offset=1)
    assert paged["total"] == 3
    assert paged["truncated"] is False
    assert [entry["definition_site"] for entry in paged["values"]] == ["0x1190", "0x1196"]
    head = uidf_list(_call(view), limit=2)
    assert head["total"] == 3
    assert head["truncated"] is True
    assert [entry["definition_site"] for entry in head["values"]] == ["0x1104", "0x1190"]
    tail = uidf_list(_call(view), limit=2, offset=2)
    assert tail["truncated"] is False
    assert [entry["variable"] for entry in tail["values"]] == ["var_10"]
    beyond = uidf_list(_call(view), offset=10)
    assert beyond == {"function": None, "total": 3, "truncated": False, "values": []}
    empty_page = uidf_list(_call(view), limit=0)
    assert empty_page["values"] == []
    assert empty_page["truncated"] is True
    assert uidf_list(_call(FakeBinaryView())) == {
        "function": None,
        "total": 0,
        "truncated": False,
        "values": [],
    }
    for kwargs, message in (
        ({"limit": -1}, "Invalid integer parameter 'limit': Must be at least 0"),
        (
            {"limit": tools._MAX_LIMIT + 1},
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}",
        ),
        ({"offset": -1}, "Invalid integer parameter 'offset': Must be at least 0"),
    ):
        with pytest.raises(FakeToolError) as exc:
            uidf_list(_call(view), **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    with pytest.raises(FakeToolError) as exc:
        uidf_list(_call(view), 0x1800)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "no analyzed function contains 0x1800"


def test_uidf_list_truncates_long_value_renders() -> None:
    view, main = _uidf_view()
    main.user_var_values[_variable(main, "rax_1")] = {
        0x1104: FakePossibleValueSet(FakeRegisterValueType.ConstantValue, "x" * 600)
    }
    _, uidf_list = get_tool("rex_uidf_list")
    result = uidf_list(_call(view))
    assert result["values"][0]["value"].endswith("chars truncated]")
