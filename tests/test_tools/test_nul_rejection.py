from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from helpers import (
    FakeParsingToolCall,
    FakeToolError,
    _call,
    _disasm_view,
    get_tool,
)
from helpers_uidf import FakeMediumLevelIL, FakeVariable
from helpers_view import (
    FakeBinaryView,
    FakeComponent,
    FakeFunction,
    FakeStructureMember,
    FakeStructureType,
    FakeType,
    RenderableText,
)

from binja_plugin import tools
from binja_plugin.tools import state

NUL_MESSAGE = "{} must not contain NUL bytes"


def _rejection(tool_name: str, view: FakeBinaryView, *arguments: Any, **keywords: Any) -> Any:
    _, tool = get_tool(tool_name)
    with pytest.raises(FakeToolError) as caught:
        tool(FakeParsingToolCall(view), *arguments, **keywords)
    return caught.value


def _assert_nul_rejected(error: FakeToolError, parameter: str) -> None:
    assert error.code == "invalid_params"
    assert error.message == NUL_MESSAGE.format(parameter)


def test_kv_delete_with_nul_in_the_key_leaves_the_truncated_key_stored() -> None:
    view = FakeBinaryView()
    _, kv_set = get_tool("rex_kv_set")
    _, kv_get = get_tool("rex_kv_get")
    kv_set(_call(view), "tri", "kept")
    _assert_nul_rejected(_rejection("rex_kv_delete", view, "tri\x00zzz"), "key")
    assert kv_get(_call(view), "tri")["value"] == "kept"


@pytest.mark.parametrize("tool_name", ["rex_kv_get", "rex_kv_set"])
def test_kv_get_and_set_reject_nul_in_the_key(tool_name: str) -> None:
    arguments = ("a\x00b", "v") if tool_name == "rex_kv_set" else ("a\x00b",)
    _assert_nul_rejected(_rejection(tool_name, FakeBinaryView(), *arguments), "key")


def test_kv_set_rejects_nul_in_the_value_before_storing_it() -> None:
    view = FakeBinaryView()
    _assert_nul_rejected(_rejection("rex_kv_set", view, "k", "a\x00b"), "value")
    with pytest.raises(FakeToolError) as caught:
        get_tool("rex_kv_get")[1](_call(view), "k")
    assert caught.value.code == "not_found"


def test_kv_set_checks_the_key_cap_before_the_value_and_nul_before_the_value_cap() -> None:
    view = FakeBinaryView()
    oversized_key = _rejection("rex_kv_set", view, "k" * 129, "a\x00b")
    assert oversized_key.code == "key_too_large"
    oversized_value = _rejection("rex_kv_set", view, "k", "\x00" * (state._MAX_KV_VALUE_CHARS + 1))
    _assert_nul_rejected(oversized_value, "value")


@pytest.mark.parametrize(
    ("title", "markdown", "parameter"),
    [("t\x00x", "body", "title"), ("title", "b\x00ody", "markdown")],
)
def test_report_show_rejects_nul_in_the_title_and_the_markdown(
    title: str, markdown: str, parameter: str
) -> None:
    _assert_nul_rejected(
        _rejection("rex_report_show", FakeBinaryView(), title, markdown), parameter
    )


@pytest.mark.parametrize(
    ("tag_type", "data", "parameter"),
    [("Fin\x00ding", "text", "tag_type"), ("Finding", "te\x00xt", "data")],
)
def test_tag_set_rejects_nul_before_creating_a_type_or_a_tag(
    tag_type: str, data: str, parameter: str
) -> None:
    view = FakeBinaryView()
    _assert_nul_rejected(_rejection("rex_tag_set", view, 0x4010, tag_type, data), parameter)
    assert view.tag_types == {}
    assert view.get_tags() == []


def _annotate_view() -> FakeBinaryView:
    return FakeBinaryView(functions=[FakeFunction("main", 0x1100, 0x1200)])


@pytest.mark.parametrize(
    ("item", "parameter"),
    [
        ({"name": "tri\x00zzz"}, "name"),
        ({"comment": "note\x00zzz"}, "comment"),
        ({"prototype": "int f(void)\x00 garbage"}, "prototype"),
        ({"addr": "0x1100\x00zzz"}, "addr"),
    ],
)
def test_annotate_many_reports_nul_per_row_and_still_applies_the_other_rows(
    item: dict[str, object], parameter: str
) -> None:
    view = _annotate_view()
    main = view.functions[0]
    _, annotate = get_tool("rex_annotate_many")
    rows = annotate(
        FakeParsingToolCall(view), [{"addr": "0x1100", **item}, {"addr": "0x1100", "name": "ok"}]
    )["results"]
    assert rows[0]["ok"] is False
    assert rows[0]["error"] == NUL_MESSAGE.format(parameter)
    assert rows[1]["ok"] is True
    assert main.name == "ok"
    assert main.comments == {}
    assert main.user_type is None


def test_component_tools_reject_nul_in_every_text_parameter() -> None:
    view = FakeBinaryView(
        functions=[FakeFunction("f", 0x1000, 0x1100)],
        component_root=FakeComponent("__root__", "guid-root"),
    )
    _assert_nul_rejected(_rejection("rex_component_create", view, "Cr\x00ypto"), "name")
    _assert_nul_rejected(
        _rejection("rex_component_create", view, "Crypto", parent_path="/a\x00b"), "parent_path"
    )
    _assert_nul_rejected(_rejection("rex_component_get", view, "/a\x00b"), "path")
    _assert_nul_rejected(
        _rejection("rex_component_add_functions", view, "/a\x00b", ["0x1000"]), "path"
    )
    _assert_nul_rejected(
        _rejection("rex_component_add_functions", view, "/", ["0x1000", "0x1000\x00zzz"]),
        "functions[1]",
    )


def test_a_nul_in_an_over_cap_text_is_reported_as_nul_not_as_too_large() -> None:
    view = FakeBinaryView(component_root=FakeComponent("__root__", "guid-root"))
    _assert_nul_rejected(_rejection("rex_component_create", view, "\x00" + "x" * 200), "name")


def test_struct_from_access_rejects_nul_before_creating_the_structure() -> None:
    view = FakeBinaryView(
        structure=FakeStructureType([FakeStructureMember("a", 0, FakeType("a"))], 4)
    )
    _assert_nul_rejected(_rejection("rex_struct_from_access", view, "ctx\x00zzz"), "name")
    assert view.defined_types == []


@pytest.mark.parametrize(
    ("arguments", "parameter"),
    [
        ({"library_name": "lib\x00zzz"}, "library_name"),
        ({"names": ["open", "op\x00en"]}, "names[1]"),
    ],
)
def test_type_library_export_rejects_nul_in_the_library_name_and_each_type_name(
    arguments: dict[str, object], parameter: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tools, "_EXPORT_ROOT", tmp_path / "exports")
    view = FakeBinaryView(types={"open": FakeType("open")})
    keywords: dict[str, Any] = {
        "library_name": "recovered",
        "names": ["open"],
        "filename": "out.bntl",
        **arguments,
    }
    _assert_nul_rejected(_rejection("rex_type_library_export", view, **keywords), parameter)
    assert not (tmp_path / "exports").exists()


def test_type_library_import_rejects_nul_in_the_path_and_each_type_name() -> None:
    view = FakeBinaryView()
    _assert_nul_rejected(_rejection("rex_type_library_import", view, "/x.bntl\x00z", ["a"]), "path")
    _assert_nul_rejected(
        _rejection("rex_type_library_import", view, "/x.bntl", ["a\x00b"]), "names[0]"
    )
    assert view.type_libraries == []


def _uidf_view() -> FakeBinaryView:
    rax_1 = FakeVariable("rax_1")
    main = FakeFunction(
        "main",
        0x1100,
        0x1200,
        hlil=RenderableText("return 0"),
        vars=[rax_1],
        mlil=FakeMediumLevelIL({rax_1: [0x1104]}),
    )
    return FakeBinaryView(functions=[main])


def test_uidf_set_rejects_nul_in_the_value_before_informing_it() -> None:
    view = _uidf_view()
    error = _rejection("rex_uidf_set", view, 0x1100, "rax_1", "0x10\x00zzz")
    _assert_nul_rejected(error, "value")
    assert view.functions[0].user_var_values == {}


def test_uidf_set_many_reports_nul_in_the_value_and_def_address_per_row() -> None:
    view = _uidf_view()
    _, uidf_set_many = get_tool("rex_uidf_set_many")
    result = uidf_set_many(
        FakeParsingToolCall(view),
        0x1100,
        [
            {"variable": "rax_1", "value": "0x10\x00zzz"},
            {"variable": "rax_1", "value": "0x10", "def_address": "0x1104\x00zzz"},
            {"variable": "rax_1", "value": "0x10", "def_address": "0x1104"},
        ],
    )
    rows = result["results"]
    assert [row["ok"] for row in rows] == [False, False, True]
    assert rows[0]["error"] == {"code": "invalid_params", "message": NUL_MESSAGE.format("value")}
    assert rows[1]["error"] == {
        "code": "invalid_params",
        "message": NUL_MESSAGE.format("def_address"),
    }
    assert len(view.functions[0].get_all_user_var_values()) == 1


def test_a_list_of_address_expressions_rejects_a_nul_entry_in_every_batch_tool() -> None:
    view = _disasm_view()
    _assert_nul_rejected(
        _rejection("rex_decompile_many", view, ["0x1100", "0x1100\x00zzz"]), "functions[1]"
    )
    _assert_nul_rejected(
        _rejection("rex_function_define_many", view, ["0x1100\x00zzz"]), "addresses[0]"
    )


def test_disasm_many_reports_a_nul_address_entry_as_its_own_error_row() -> None:
    _, disasm_many = get_tool("rex_disasm_many")
    result = disasm_many(FakeParsingToolCall(_disasm_view()), ["0x1100", "0x1100\x00zzz"])
    assert [window["index"] for window in result["windows"]] == [0]
    assert [(error["index"], error["error"]) for error in result["errors"]] == [
        (1, {"code": "invalid_params", "message": NUL_MESSAGE.format("addresses[1]")})
    ]


def test_a_section_name_with_nul_stays_section_not_found() -> None:
    view = FakeBinaryView(sections={".text": (0x1000, 0x1004)})
    error = _rejection("rex_string_search", view, section=".text\x00z")
    assert error.code == "section_not_found"
